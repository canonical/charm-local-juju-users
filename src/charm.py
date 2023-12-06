#!/usr/bin/env python3
# Copyright 2023 Canonical
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Automate synchronization of local UNIX group users with Juju accounts."""

import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Any

import ops
import yaml
from local_juju_users import (
    ConfigRenderer,
    JujuClient,
    create_home_dir_if_missing,
    customize_bashrc,
    generate_random_password,
    get_linux_group_users,
    get_users_primary_group,
    linux_group_exists,
    linux_user_exists,
    parse_controller_model,
    read_clouds_file,
    read_credentials_file,
    save_clouds_file,
    save_credentials_file,
    setup_juju_data_dir,
    setup_ssh_config,
    setup_ssh_key,
    su,
    sync_path,
)
from ops.main import main
from pkg_resources import packaging

# Log messages can be retrieved using juju debug-log
log = logging.getLogger(__name__)

PEER = "local-juju-users"

JUJU_3_RUN_ACTION_CMD = ["/snap/bin/juju", "run", "--wait=15m"]
JUJU_2_RUN_ACTION_CMD = ["/snap/bin/juju", "run-action", "--wait"]


class LocalJujuUsersCharm(ops.charm.CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.upgrade_charm, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on[PEER].relation_changed, self._on_peer_data_changed)

        # Actions
        self.framework.observe(self.on.synchronize_accounts_action, self._synchronize_accounts)

        self.renderer = ConfigRenderer("templates")
        self.can_sync = False

        # FIXME: validate this user account
        self.juju_client = JujuClient(self.model.config["juju-admin-unix-account"])

    def _on_install(self, _):
        """Install the required packages."""
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"

        cmd = ["apt-get", "update"]
        subprocess.check_call(cmd, universal_newlines=True)

        cmd = ["apt-get", "install", "-y", "rsync"]
        subprocess.check_call(cmd, universal_newlines=True)

    def _assess_status(self):
        """Assess the status of this unit."""
        # TODO: Validate charm config?

        self.can_sync = False

        # Check if the source unix group exists.
        unix_group = self.model.config["source-unix-group"]
        if not linux_group_exists(unix_group):
            self.unit.status = ops.model.BlockedStatus(
                "Source UNIX group {} does not exist".format(unix_group)
            )
            return

        # Check if the source unix group has any members.
        unix_group_members = get_linux_group_users(unix_group)
        if len(unix_group_members) == 0:
            self.unit.status = ops.model.BlockedStatus(
                "Source UNIX group '{}' does not have any members".format(unix_group)
            )
            return

        # Check if the source unix group members are identical on all units.
        if not self._validate_user_lists():
            self.unit.status = ops.model.BlockedStatus(
                "UNIX group '{}' members are not identical on all units".format(unix_group)
            )
            return

        # Check if the juju admin user exists.
        juju_admin = self.model.config["juju-admin-unix-account"]
        if not linux_user_exists(juju_admin):
            self.unit.status = ops.model.BlockedStatus(
                "juju-admin-unix-account '{}' does not exist".format(juju_admin)
            )
            return

        # Check if juju cli is installed.
        if not self.juju_client.juju_cli_available:
            self.unit.status = ops.model.BlockedStatus("Juju CLI client not available")
            return

        # Check if the juju admin user has access to all juju controllers.
        whoami = self.juju_client.whoami()
        if not self.juju_client.is_controller_superuser(whoami["controller"], whoami["user"]):
            self.unit.status = ops.model.BlockedStatus(
                "Juju admin UNIX user '{}' does not have access to controller '{}'".format(
                    juju_admin, whoami["controller"]
                )
            )
            return

        # Check if clouds.yaml and credentials.yaml files are available.
        credentials = self._get_peer_data("credentials")
        clouds = self._get_peer_data("clouds")
        if not credentials or not clouds:
            self.unit.status = ops.model.BlockedStatus(
                "credentials.yaml and clouds.yaml not available in the relation data"
            )
            return

        # We are ready to start synchronizing accounts.
        # Check the last time the accounts were synchronized on this unit.
        self.can_sync = True
        last_sync_timestamp = self._get_last_sync_timestamp()

        # Set the active status with no message when all is well
        self.unit.status = ops.model.ActiveStatus(
            "ready (last sync: {})".format(last_sync_timestamp)
        )

    def _setup_cron(self):
        """Set up cron job to synchronize accounts."""
        cron_schedule = self.model.config["sync-schedule"]

        juju_run_action_args = ["-m", self.model.name, self.unit.name, "synchronize-accounts"]
        if self.juju_client.juju_cli_version < packaging.version.parse("3.0.0"):
            juju_cmd = JUJU_2_RUN_ACTION_CMD + juju_run_action_args
        else:
            juju_cmd = JUJU_3_RUN_ACTION_CMD + juju_run_action_args

        self.renderer.render(
            "cron.j2",
            "/etc/cron.d/local-juju-users-sync",
            {
                "cron_schedule": cron_schedule,
                "cron_user": self.config["juju-admin-unix-account"],
                "cron_command": " ".join(juju_cmd),
            },
        )

    def _on_config_changed(self, event: ops.charm.ConfigChangedEvent):
        # FIXME: validate config
        self._update_relation_data()
        self._setup_cron()
        self._assess_status()

    def _on_update_status(self, event: ops.charm.UpdateStatusEvent):
        self._update_relation_data()
        self._assess_status()

    def _on_peer_data_changed(self, event: ops.charm.RelationChangedEvent):
        self._assess_status()

    @property
    def peers(self):
        """Fetch the peer relation."""
        return self.model.get_relation(PEER)

    def _set_peer_data(self, key: str, data: Any) -> None:
        if self.peers:
            self.peers.data[self.app][key] = json.dumps(data)

    def _set_peer_unit_data(self, key: str, data: Any) -> None:
        if self.peers:
            self.peers.data[self.unit][key] = json.dumps(data)

    def _get_peer_data(self, key: str) -> Any:
        if not self.peers:
            return {}
        data = self.peers.data[self.app].get(key, "")
        return json.loads(data) if data else {}

    def _get_peer_unit_data(self, unit, key: str) -> None:
        if not self.peers:
            return {}
        data = self.peers.data[unit].get(key, "")
        return json.loads(data) if data else {}

    def _store_password(self, username, password):
        """Store the password in the peer relation data."""
        data = {"password": password}
        self._set_peer_data(username, data)

    def _retrieve_password(self, username):
        """Retrieve the password from the peer relation data."""
        data = self._get_peer_data(username)
        return data.get("password", None)

    def _validate_user_lists(self):
        """Ensure that the unix group members are identical on all peers."""
        if not self.peers:
            return True

        # Update local user list in the peer relation data
        source_unix_group = self.model.config["source-unix-group"]
        local_users = get_linux_group_users(source_unix_group)
        self._set_peer_unit_data("local_users", local_users)

        # Compare with other peers
        for peer in self.peers.units:
            peer_users = self._get_peer_unit_data(peer, "local_users")
            # FIXME: check order of this list, parse and sort or something
            if local_users != peer_users:
                return False

        return True

    def _get_last_sync_timestamp(self):
        timestamp_str = self._get_peer_unit_data(self.unit, "last_sync_timestamp")
        if not timestamp_str:
            return "never"
        return timestamp_str

    def _update_relation_data(self):
        """Update the relation data with the current state of the unit."""
        # save local user list in the peer relation data
        source_unix_group = self.model.config["source-unix-group"]
        current_linux_users = get_linux_group_users(source_unix_group)
        self._set_peer_unit_data("local_users", current_linux_users)
        if not self._validate_user_lists():
            self.unit.status = ops.model.BlockedStatus(
                "UNIX group {} members are not identical on all units".format(source_unix_group)
            )
            return

        # on the leader load admin's clouds.yaml and credentials.yaml files so that they can be distributed to other users
        if self.unit.is_leader():
            credentials = read_credentials_file(self.model.config["juju-admin-unix-account"])
            if self._get_peer_data("credentials") != credentials:
                self._set_peer_data("credentials", credentials)

            clouds = read_clouds_file(self.model.config["juju-admin-unix-account"])
            if self._get_peer_data("clouds") != clouds:
                self._set_peer_data("clouds", clouds)

    def _get_default_controller_model(self):
        """Return the default model."""
        if self.config["default-juju-model"]:
            default_controller, default_model = parse_controller_model(
                self.config["default-juju-model"]
            )
        elif self.juju_client.controllers:
            default_controller = list(self.juju_client.controllers.keys())[0]
            default_model = self.juju_client.models(default_controller)[0]["name"]
        else:
            default_controller, default_model = None, None

        return default_controller, default_model

    def _get_ignored_controllers(self):
        """Return the user-specified ignored controllers list."""
        if (
            self.model.config["ignored-controllers"]
            and len(self.model.config["ignored-controllers"].strip()) > 0
        ):
            return [
                controller.strip()
                for controller in self.model.config["ignored-controllers"].split(",")
            ]

        return []

    def _disable_accounts(self):
        """Disable accounts that are no longer needed."""
        ignored_accounts = self.config["ignored-accounts"]
        current_linux_users = get_linux_group_users(self.config["source-unix-group"])

        for controller in self.juju_client.controllers:
            for user in self.juju_client.controller_users(controller):
                if (
                    user["user-name"] not in current_linux_users
                    and user["user-name"] not in ignored_accounts
                ):
                    log.info("Disabling user {}".format(user["user-name"]))
                    controller_models = self.juju_client.models(controller)
                    for model in controller_models:
                        if model["model-type"] != "caas":
                            self.juju_client.remove_ssh_keys(
                                controller, model["name"], user["user-name"]
                            )
                        if self.juju_client.is_user_model_admin(
                            controller, model["name"], user["user-name"]
                        ):
                            self.juju_client.revoke_user_model_access(
                                controller, model["name"], user["user-name"]
                            )
                    self.juju_client.disable_user(controller, user["user-name"])

    def _setup_juju_user_access(self, user, password):
        for controller in self.juju_client.controllers:
            controller_models = self.juju_client.models(controller)
            # set up access
            if self.juju_client.user_exists(controller, user):
                print("Juju user {} already exists".format(user))
                if self.juju_client.get_user(controller, user).get("disabled", None):
                    print("Enabling user {}".format(user))
                    self.juju_client.enable_user(controller, user)
            else:
                self.juju_client.add_user(controller, user)

            if not self.juju_client.is_controller_superuser(controller, user):
                self.juju_client.grant_superuser_access(controller, user)

            for model in controller_models:
                if not self.juju_client.is_user_model_admin(controller, model["name"], user):
                    self.juju_client.grant_user_model_admin_access(controller, model["name"], user)

            self.juju_client.set_password(controller, user, password)

    def _generate_model_filename(self, controller, model, user):
        if len(self.juju_client.controllers) > 1:
            model_filename = "/home/{}/model.{}-{}".format(user, controller, model.split("/")[-1])
        else:
            model_filename = "/home/{}/model.{}".format(user, model.split("/")[-1])
        return model_filename

    def _sync_extra_paths(self, user):
        """Sync extra paths from the config."""
        extra_paths = self.model.config["sync-extra-paths"]
        if not extra_paths:
            return

        try:
            paths = yaml.safe_load(extra_paths)
        except Exception as e:
            log.error("Failed to parse sync-extra-paths: {}".format(e))
            return

        for path in paths:
            try:
                src, dst = path.split(":")
                # rewrite $USER in the dst path
                dst = dst.replace("$USER", user)
                sync_path(src, dst, user)
            except Exception as e:
                log.warning("Skipping files sync {}. Failed to sync: {}".format(path, e))

    def _synchronize_accounts(self, event: ops.charm.ActionEvent):
        source_unix_group = self.model.config["source-unix-group"]
        self.model.config["ignored-accounts"]
        ignored_controllers = self._get_ignored_controllers()
        default_model = self.model.config["default-juju-model"]  # FIXME: ensure this model exists

        # sync the local user list and other details with other peers
        self._update_relation_data()

        # run pre-checks
        self._assess_status()
        if not self.can_sync:
            print("Sync failed: {}".format(self.unit.status.message))  # FIXME: log
            return

        default_controller, default_model = self._get_default_controller_model()

        # obtain the list of local users
        current_linux_users = get_linux_group_users(source_unix_group)
        for user in current_linux_users:
            # try running `whoami` as the user, back out if it fails
            # side effect is that the home dir will be created if it doesn't exist
            try:
                su(user)
                create_home_dir_if_missing(user)
            except Exception as e:
                log.error("Failed to switch to user {}: {}".format(user, e))
                self.unit.status = ops.model.BlockedStatus(
                    "Couldn't switch to user {} on the system".format(user)
                )
                return

            # retrieve user's password from the relation data or set a new one
            password = self._retrieve_password(user)
            if not password:
                if self.unit.is_leader():
                    password = generate_random_password()
                    self._store_password(user, password)
                else:
                    self.unit.status = ops.model.BlockedStatus(
                        "Password of Juju user {} not yet configured by the leader".format(user)
                    )
                    return

            # ensure that ssh key and config exists, create if needed
            setup_ssh_key(user)
            setup_ssh_config(user)

            # only the leader is responsible for setting up access to juju
            if self.unit.is_leader():
                self._setup_juju_user_access(user, password)

            # create all YAML files needed to access Juju
            setup_juju_data_dir(user)

            self.renderer.render(
                "accounts.yaml.j2",
                "/home/{}/.local/share/juju/accounts.yaml".format(user),
                {
                    "user": user,
                    "password": password,
                    "controllers": self.juju_client.controllers,
                },
                user=user,
                group=get_users_primary_group(user),
                permissions=0o600,
            )

            self.renderer.render(
                "controllers.yaml.j2",
                "/home/{}/.local/share/juju/controllers.yaml".format(user),
                {
                    "controllers": self.juju_client.controllers,
                    "current_controller": default_controller,
                },
                user=user,
                group=get_users_primary_group(user),
                permissions=0o600,
            )

            # contents of clouds.yaml and credentials.yaml are just copied and pasted from the admin
            # since they are not user-specific
            credentials = self._get_peer_data("credentials")
            clouds = self._get_peer_data("clouds")
            save_credentials_file(user, credentials)
            save_clouds_file(user, clouds)

            # register local ssh keys and render bashrc and model.* files on all units
            for controller in self.juju_client.controllers:
                if controller not in ignored_controllers:
                    controller_models = self.juju_client.models(controller)
                    for model in controller_models:
                        # registering ssh keys is supported only in non-container models
                        if model["model-type"] != "caas":
                            self.juju_client.register_ssh_key(controller, model["name"], user)

                        self.renderer.render(
                            "model.j2",
                            self._generate_model_filename(controller, model["name"], user),
                            {
                                "controller": controller,
                                "model": model["name"],
                            },
                            user=user,
                            group=get_users_primary_group(user),
                            permissions=0o644,
                        )

            # customize bash prompt
            sitename = self.model.config["site-name"]
            customize_bashrc(
                user,
                sitename,
                self._generate_model_filename(default_controller, default_model, user),
            )

            # sync any additional files
            self._sync_extra_paths(user)

        # finally, disable accounts that are no longer needed
        if self.unit.is_leader():
            self._disable_accounts()

        # update the last sync timestamp
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._set_peer_unit_data("last_sync_timestamp", timestamp_str)
        self._on_update_status(event)

        # TODO: record failed sync attempt?


if __name__ == "__main__":  # pragma: nocover
    main(LocalJujuUsersCharm)

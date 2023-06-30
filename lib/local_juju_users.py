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

"""Utility library for managing Juju user accounts."""

import base64
import os
import pwd
import random
import re
import shutil
import socket
import stat
import string
import subprocess

import yaml
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jinja2 import Environment, FileSystemLoader
from pkg_resources import packaging


def set_owner_and_permissions(path, user, group, permissions):
    """Set owner and permissions for a file or directory."""
    if os.path.exists(path):
        current_owner = os.stat(path).st_uid
        current_group = os.stat(path).st_gid
        desired_owner = pwd.getpwnam(user).pw_uid
        desired_group = pwd.getpwnam(user).pw_gid
        if current_owner != desired_owner or current_group != desired_group:
            shutil.chown(path, user, group)

        current_permissions = stat.S_IMODE(os.lstat(path).st_mode)
        if current_permissions != permissions:
            os.chmod(path, permissions)


class ConfigRenderer:
    """Helper class to render a template to a file."""

    def __init__(self, template_dir) -> None:
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        pass

    def render(self, template, target, context, user="root", group="root", permissions=0o644):
        """Render a template to a file."""
        template = self.env.get_template(template)
        with open(target, "w") as f:
            f.write(template.render(context))
        set_owner_and_permissions(target, user, group, permissions)


def get_linux_group_users(group):
    """Return a list of users belonging to a group on the system."""
    cmd = ["getent", "group", group]
    raw_output = subprocess.check_output(cmd)
    output = raw_output.decode().rstrip()
    users_field = output.rstrip().split(":")[3]
    users = users_field.split(",")
    return list(filter(None, users))


def linux_group_exists(group):
    """Return True if the group exists on the system."""
    cmd = ["getent", "group", group]
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError:
        return False


def get_users_primary_group(user):
    """Return the primary group of a user."""
    cmd = ["id", "-gn", user]
    raw_output = subprocess.check_output(cmd)
    output = raw_output.decode().rstrip()
    return output


def create_home_dir_if_missing(user):
    """Create a home directory for a user."""
    home_dir = "/home/{}".format(user)
    if not os.path.exists(home_dir):
        if os.path.exists("/etc/skel"):
            shutil.copytree("/etc/skel", home_dir)
        else:
            os.makedirs(home_dir, mode=0o700)
        set_owner_and_permissions(home_dir, user, get_users_primary_group(user), 0o700)


def su(user):
    """Run su."""
    # Note: This will create a home directory for the user if it doesn't exist.
    cmd = ["su", "-c", "whoami", user]
    subprocess.check_call(cmd)


def linux_user_exists(user):
    """Return True if the user exists on the system."""
    cmd = ["getent", "passwd", user]
    try:
        subprocess.check_call(cmd)
        return True
    except subprocess.CalledProcessError:
        return False


def setup_juju_data_dir(user):
    """Set up the Juju data directory for a user."""
    juju_dir = "/home/{}/.local/share/juju".format(user)

    # Check if the directory already exists
    if not os.path.exists(juju_dir):
        os.makedirs(juju_dir, mode=0o700)

    primary_group = get_users_primary_group(user)
    set_owner_and_permissions("/home/{}/.local".format(user), user, primary_group, 0o700)
    set_owner_and_permissions("/home/{}/.local/share".format(user), user, primary_group, 0o700)
    set_owner_and_permissions(juju_dir, user, primary_group, 0o700)


def setup_ssh_key(user):
    """Set up an SSH key for a user."""
    ssh_dir_path = "/home/{}/.ssh".format(user)
    private_key_path = "{}/personal_juju_id_ecdsa".format(ssh_dir_path)
    public_key_path = "{}/personal_juju_id_ecdsa.pub".format(ssh_dir_path)

    keypair_exists = os.path.isfile(private_key_path) and os.path.isfile(public_key_path)

    primary_group = get_users_primary_group(user)

    if not keypair_exists:
        if not os.path.isdir(ssh_dir_path):
            os.makedirs(ssh_dir_path, mode=0o700)

        private_key, public_key = generate_ssh_key_pair(user)
        with open(private_key_path, "w") as f:
            f.write(private_key)
        with open(public_key_path, "w") as f:
            f.write(public_key)

    set_owner_and_permissions(ssh_dir_path, user, primary_group, 0o700)
    set_owner_and_permissions(private_key_path, user, primary_group, 0o600)
    set_owner_and_permissions(public_key_path, user, primary_group, 0o644)


def get_ssh_key(user):
    """Return the SSH key for a user."""
    # TOFIX: home dir location?
    # TOFIX: make sure the key exists
    public_key_path = "/home/{}/.ssh/personal_juju_id_ecdsa.pub".format(user)
    with open(public_key_path, "r") as f:
        public_key = f.read()
    return public_key


def setup_ssh_config(user):
    """Set up an SSH config for a user."""
    get_users_primary_group(user)
    renderer = ConfigRenderer("templates")
    renderer.render(
        "ssh_config.j2",
        "/home/{}/.ssh/config".format(user),
        {},
        user=user,
        group=get_users_primary_group(user),
    )


def encode_file_to_base64(file_path):
    """Return the contents of a base64 encoded file as a string."""
    with open(file_path, "rb") as file:
        file_contents = file.read()
        encoded_contents = base64.b64encode(file_contents)
        return encoded_contents.decode("utf-8")


def save_base64_to_file(base64_string, file_path):
    """Save a string as a base64 encoded file."""
    decoded_contents = base64.b64decode(base64_string)
    with open(file_path, "wb") as file:
        file.write(decoded_contents)


def read_clouds_file(user):
    """Return the clouds.yaml as base64 encoded string."""
    clouds_file = "/home/{}/.local/share/juju/clouds.yaml".format(user)
    try:
        return encode_file_to_base64(clouds_file)
    except FileNotFoundError:
        # return dummy empty clouds in the expected format
        return base64.b64encode(b"clouds: {}")


def read_credentials_file(user):
    """Return the clouds.yaml as base64 encoded string."""
    credentials_file = "/home/{}/.local/share/juju/credentials.yaml".format(user)
    try:
        return encode_file_to_base64(credentials_file)
    except FileNotFoundError:
        # return dummy empty credentials in the expected format
        return base64.b64encode(b"credentials: {}")


def save_clouds_file(user, clouds):
    """Save the base64 encoded clouds.yaml to a file."""
    clouds_file = "/home/{}/.local/share/juju/clouds.yaml".format(user)
    save_base64_to_file(clouds, clouds_file)
    set_owner_and_permissions(clouds_file, user, get_users_primary_group(user), 0o600)


def save_credentials_file(user, credentials):
    """Save the base64 encoded credentials.yaml to a file."""
    credentials_file = "/home/{}/.local/share/juju/credentials.yaml".format(user)
    save_base64_to_file(credentials, credentials_file)
    set_owner_and_permissions(credentials_file, user, get_users_primary_group(user), 0o600)


def generate_ssh_key_pair(user):
    """Generate an ECDSA SSH key pair."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()  # Use the NIST P-256 elliptic curve
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    hostname = socket.gethostname()
    comment = " personal-juju-key-{}-{}".format(user, hostname)
    public_key += comment.encode("utf-8")

    return private_key_pem.decode("utf-8"), public_key.decode("utf-8")


def generate_random_password(password_length=20):
    """Generate a random password of a given length."""
    password = "".join(random.choices(string.ascii_letters + string.digits, k=password_length))
    return password


def customize_bashrc(user, sitename, default_model_filename):
    """Customize the bash prompt for a user."""
    # render an extra file with bash prompt and other customizations
    renderer = ConfigRenderer("templates")
    renderer.render(
        "bashrc.j2",
        "/home/{}/.bashrc_local_juju_users".format(user),
        {
            "sitename": sitename,
            "default_model_filename": default_model_filename,
            "user": user,
        },
        user=user,
        group=get_users_primary_group(user),
    )

    # source this file in .bashrc
    source_line = "if [ -f ~/.bashrc_local_juju_users ]; then source ~/.bashrc_local_juju_users; fi # local-juju-users-bashrc"
    regex_pattern = r"local-juju-users-bashrc"
    file_path = "/home/{}/.bashrc".format(user)
    with open(file_path, "r") as file:
        file_contents = file.readlines()
    pattern_matched = any(re.search(regex_pattern, line) for line in file_contents)
    if not pattern_matched:
        file_contents.append(source_line + "\n")
    with open(file_path, "w") as file:
        file.writelines(file_contents)


def parse_controller_model(controller_model):
    """Parse a controller:user/model string."""
    try:
        default_controller = controller_model.split(":")[0]
        default_model = controller_model.split(":")[1]
        return default_controller, default_model
    except IndexError:
        return "", ""


def recursive_chown(target, user):
    """Recursively chown a directory."""
    for dir, _, filenames in os.walk(target):
        shutil.chown(dir, user, get_users_primary_group(user))
        for filename in filenames:
            shutil.chown(os.path.join(dir, filename), user, get_users_primary_group(user))


def sync_path(source, destination, user):
    """Sync files from source to destination."""
    cmd = ["rsync", "-avz", source, destination]
    subprocess.check_call(cmd)
    if os.path.isdir(destination):
        recursive_chown(destination, user)
    else:
        shutil.chown(destination, user, get_users_primary_group(user))


class JujuClient:
    """Helper class to manage Juju users."""

    def __init__(self, run_as) -> None:
        self.run_as = run_as
        self.cmd_run_as = ["sudo", "-u", self.run_as]

        # it makes sense to cache these and obtain them only once
        self.controllers = self.get_controllers()

        self.ssh_keys = {}

    @property
    def juju_cli_available(self):
        """Return True if the Juju CLI is available."""
        cmd = self.cmd_run_as + ["juju", "version"]
        try:
            subprocess.check_call(cmd)
            return True
        except subprocess.CalledProcessError:
            return False

    @property
    def juju_cli_version(self):
        """Return the Juju client version."""
        cmd = self.cmd_run_as + ["juju", "version"]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip().split("-")[0]
        juju_version = packaging.version.parse(output)
        return juju_version

    def get_controllers(self):
        """Return a list of Juju controllers."""
        cmd = self.cmd_run_as + ["juju", "controllers", "--format", "yaml"]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip()
        yaml_output = yaml.safe_load(output)
        try:
            controllers = yaml_output["controllers"]
        except KeyError:
            controllers = []
        return controllers

    def controller_users(self, controller):
        """Return a list of Juju users for a controller."""
        cmd = self.cmd_run_as + ["juju", "users", "--format", "yaml", "-c", controller, "--all"]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip()
        users = yaml.safe_load(output)
        return users

    def add_user(self, controller, username):
        """Create a Juju user for a controller."""
        cmd = self.cmd_run_as + ["juju", "add-user", "-c", controller, username]
        subprocess.check_call(cmd)

    def user_exists(self, controller, username):
        """Return True if the Juju user exists for a controller."""
        cmd = self.cmd_run_as + [
            "juju",
            "show-user",
            username,
            "--format",
            "yaml",
            "-c",
            controller,
        ]
        try:
            subprocess.check_call(
                cmd,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def get_user(self, controller, username):
        """Return the Juju user for a controller."""
        cmd = self.cmd_run_as + [
            "juju",
            "show-user",
            username,
            "--format",
            "yaml",
            "-c",
            controller,
        ]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip()
        user = yaml.safe_load(output)
        return user

    def models(self, controller):
        """Return a list of Juju models for a controller."""
        cmd = self.cmd_run_as + ["juju", "models", "--format", "yaml", "-c", controller]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip()
        yaml_output = yaml.safe_load(output)
        try:
            models = yaml_output["models"]
        except KeyError:
            models = []
        return models

    def set_password(self, controller, user, password):
        """Set the password for a Juju user on a controller."""
        cmd = self.cmd_run_as + ["juju", "--debug", "change-user-password", "-c", controller, user]
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _, stderr = process.communicate(input=(password + "\n" + password + "\n").encode())

        # Check for any errors
        if process.returncode != 0:
            print(f"Error running the command: {stderr.decode()}")
            # TOFIX: raise exception
            raise OSError("Password change for user {} failed: {}".format(user, stderr.decode()))

    def grant_superuser_access(self, controller, user):
        """Grant superuser access to a Juju user for a controller."""
        cmd = self.cmd_run_as + ["juju", "grant", "-c", controller, user, "superuser"]
        subprocess.check_call(cmd)

    def grant_user_model_admin_access(self, controller, model, user):
        """Grant model admin access to a Juju user for a controller."""
        cmd = self.cmd_run_as + ["juju", "grant", user, "admin", model, "-c", controller]
        subprocess.check_call(cmd)

    def disable_user(self, controller, user):
        """Disable a Juju user for a controller. Deleting would be problematic because of LP#1770370."""
        cmd = self.cmd_run_as + ["juju", "disable-user", user, "-c", controller]
        subprocess.check_call(cmd)

    def enable_user(self, controller, user):
        """Enable a Juju user for a controller."""
        cmd = self.cmd_run_as + ["juju", "enable-user", user, "-c", controller]
        subprocess.check_call(cmd)

    def controller_model_users(self, controller, model):
        """Return a list of Juju users and their persmissions for a model."""
        cmd = self.cmd_run_as + ["juju", "users", "-c", controller, model, "--format", "yaml"]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip()
        users = yaml.safe_load(output)
        return users

    def is_controller_superuser(self, controller, username):
        """Return True if the Juju user is a superuser for a controller."""
        controller_users = self.controller_users(controller)
        user = next((item for item in controller_users if item["user-name"] == username), None)
        if user is not None and user["access"] == "superuser":
            return True
        return False

    def is_user_model_admin(self, controller, model, username):
        """Return True if the Juju user is a model admin for a model."""
        model_users = self.controller_model_users(controller, model)
        try:
            if model_users[username]["access"] == "admin":
                return True
        except KeyError:
            # we should never get here
            print("User {} not found in model {}".format(username, model))
        return False

    def revoke_user_model_access(self, controller, model, user):
        """Revoke model access from a Juju user for a controller."""
        levels = ["admin", "read", "write"]
        for level in levels:
            cmd = self.cmd_run_as + ["juju", "revoke", user, level, model, "-c", controller]
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError as e:
                print(
                    "Error revoking {} access for user {} in model {}: {}".format(
                        level, user, model, e
                    )
                )

    def register_ssh_key(self, controller, model, user):
        """Register an SSH key for a Juju user for a model."""
        # FIXME: don't try to register if it's already there
        public_ssh_key = get_ssh_key(user)
        cmd = self.cmd_run_as + [
            "juju",
            "add-ssh-key",
            "-m",
            "{}:{}".format(controller, model),
            public_ssh_key,
        ]
        subprocess.check_call(cmd)

    def get_ssh_keys(self, controller, model):
        """List SSH keys of a Juju user for a model."""
        if controller not in self.ssh_keys:
            self.ssh_keys[controller] = {}

        if model not in self.ssh_keys[controller]:
            self.ssh_keys[controller][model] = []
        else:
            return self.ssh_keys[controller][model]

        list_cmd = self.cmd_run_as + [
            "juju",
            "ssh-keys",
            "--full",
            "-m",
            "{}:{}".format(controller, model),
        ]
        raw_output = subprocess.check_output(
            list_cmd,
        )
        output = raw_output.decode().rstrip()

        for key in output.splitlines():
            self.ssh_keys[controller][model].append(key.rstrip())

        return output

    def remove_ssh_keys(self, controller, model, user):
        """Remove SSH keys of a Juju user from a model."""
        keys = self.get_ssh_keys(controller, model)
        key_comment_substring = "personal-juju-key-{}".format(user)
        for key in keys:
            if key_comment_substring in key:
                cmd = self.cmd_run_as + [
                    "juju",
                    "remove-ssh-key",
                    "-m",
                    "{}:{}".format(controller, model),
                    key.split(" ")[-1],
                ]
                subprocess.check_call(cmd)

    def whoami(self):
        """Return the Juju user."""
        cmd = self.cmd_run_as + ["juju", "whoami", "--format", "yaml"]
        raw_output = subprocess.check_output(cmd)
        output = raw_output.decode().rstrip()
        whoami = yaml.safe_load(output)
        return whoami

# Local Juju Users

A subordinate charm for syncing Juju accounts and local UNIX group users.

The charm creates Juju account for every local UNIX group member, gives them admin access to all locally available controllers and models, sets up SSH keys and adds them to all models.

Supports Ubuntu 18.04, 20.04 and 22.04 releases. It has been tested against Juju 2.9 and Juju 3.0.

## Installation

```shell
juju deploy ch:local-juju-users local-juju-users
juju relate local-juju-users <principal-charm>
```

## Configuration

```shell
juju config local-juju-users <option>=<value>
```

Available configuration options:

| Name | Description | Examples | Default |
|---|---|---|---|
| `source-unix-group` | The UNIX group that will be used to source the list of users to be added to the juju model. | `sre-squad` | `ubuntu` |
| `ignored-accounts` | A comma separated list of Juju accounts that will be ignored by the charm. | `admin,prometheus-juju-exporter` | `admin` |
| `juju-admin-unix-account` | The UNIX account that will be used to add users to the juju model. | `ubuntu` | `ubuntu` |
| `sync-schedule` | User account sync schedule in cron format. | `"10,25,40,55 * * * *"` `"@daily"` `"@hourly"` | `"@daily"` |
| `site-name` | This is the name that will be used to identify the remote site in the bash prompt. It can be useful to set this to the name of the cloud or datacenter location. | `Example-West-1` | `Juju` |
| `default-juju-model` | The Juju model that will be used as the default model when accessing juju for the first time. If empty, the first available controller and model will be selected. | `"foundations-maas:admin/openstack"` | `""` |
| `sync-extra-paths` | A list of paths to files and directories to be synced between "juju-admin-unix-account" and "source-unix-group" members. The expected format is a YaML list of `<source>:<destination>` strings. The underlying tool used for syncing these files is `rsync`.  | `["/home/ubuntu/admin.novarc:/home/$USER/admin.novarc", "/home/ubuntu/.kube/:/home/$USER/.kube"]` | `""` |

## Usage

To sync user accounts manually, run the `synchronize-accounts` action.

```shell
# on Juju 2.9
juju run-action --wait local-juju-users/leader synchronize-accounts
# on Juju 3.0
juju run --wait=15m local-juju-users/leader synchronize-accounts
```

Note: The first sync should be executed on the leader since it's responsible for setting up access to the controllers and generating passwords. Sync attempts on non-leaders will fail until the first full sync on the leader completes successfully.

Note 2: The charm sets up a cron job that will attempt to sync accounts periodically, based on the interval defined in the `sync-schedule` config option.

## Other resources

- More information: https://charmhub.io/local-juju-users
- Charmhub package name: local-juju-users
- [Contributing](CONTRIBUTING.md)

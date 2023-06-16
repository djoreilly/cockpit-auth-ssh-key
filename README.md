Rewrite of Python [cockpit-auth-ssh-key](https://github.com/cockpit-project/cockpit/blob/main/containers/ws/cockpit-auth-ssh-key) in Rust.

# Howto test
Pick a ssh key which has a passphase, the example below uses `~/.ssh/id_rsa`.
Add the pub key to `~/.ssh/authorized_keys` on some target host that has cockpit bridge installed.
Here the `default-bastion.conf` is replaced with one that points to the Rust cockpit-auth-ssh-key.

```
$ cargo build

$ docker run -d --rm \
  --name cockpit-bastion \
  -e RUST_LOG=debug \
  -e COCKPIT_SSH_KEY_PATH=/id_rsa \
  -v $HOME/.ssh/id_rsa:/id_rsa:ro \
  -v $PWD/default-bastion.conf:/container/default-bastion.conf \
  -v $PWD/target/debug/:/work \
  -p 9090:9090 \
  quay.io/cockpit/ws

$ docker logs -f cockpit-bastion

$ firefox https://localhost:9090
```

In the browser dialog, set `User name` to the user of the target host. Set `Password` to the passphrase for the ssh key. Set `Connect to` to the target host.
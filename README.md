nixos-shell
===========

A tool for reproducable development environments
described as NixOS modules.

It fits somewhere between `nix-shell` and `nixos-rebuild build-vm`.

Why
---

It solves the same problem as things like virtualenv, 
RVM and to a certain extent Docker: The issue of quickly
being able to enter an environment with all the
dependecies you need for working on your application.

How
---

You add a `configuration.nix` file to each of your 
applications. Then when you want to work on an 
application you navigate to your project and boot a container:

```
$ cd my-awesome-project
$ sudo nixos-shell
[root@10.0.2.12]$ echo "I'm in a container"
```

A container is built as defined in your project's `configuration.nix`,
spawned, and you are logged in via SSH. The container has a
private networking namespace so you can start multiple containers
with clashing ports.

You can access things running in the container from the advertised IP.


Install
-------

```
$ git clone https://github.com/chrisfarms/nixos-shell.git
$ cd nixos-shell
$ nix-env -f default.nix
```

FAQ
---

####Isn't this just nix-shell?
No. `nix-shell` will drop you into a chroot, with any required build
dependencies, but won't handle dependent *services*. `nixos-shell` will 
drop you into a *containter* which is closer to booting a virtual machine
with everything you need.

####Isn't this just nixos-container?
Not quite. `nixos-shell` is for spawning ephemeral `nixos-container`'s.
That is, it sets up your container, gets you logged in, then takes care of
tearing it up and tidying up after you when you log out.



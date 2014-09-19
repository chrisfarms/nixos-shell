nixos-shell
===========

A tool for reproducable development environments
described as NixOS modules.

It fits somewhere between `nix-shell` and `nixos-rebuild build-vm`.

Why
---

It solves the same problem as things like [virtualenv](http://virtualenv.readthedocs.org/en/latest/virtualenv.html), 
[RVM](http://rvm.io/) and tools like [Vagrant](https://www.vagrantup.com/): The issue of quickly
being able to enter an environment with all the
dependecies you need for working on your application without
polluting your environment.

How
---

You add a `configuration.nix` file to each of your 
applications. Then when you want to work on an 
application you navigate to your project and boot a container:

```
$ cd my-awesome-project
$ sudo nixos-shell
[10.0.2.12:/src]$ echo "I'm in a container"
```

A container is built as defined in your project's `configuration.nix`,
spawned, and you are logged in via SSH. The container has a
private networking namespace so you can start multiple containers
with clashing ports.

You can access things running in the container from the host via
the ip address advertised in the bash prompt.

Your application dir (the path on the host where you ran `nixos-shell`) 
is bind mounted to `/src` inside the container. This is analgous to
the `/vagrant` [synced folder in vagrant](https://docs.vagrantup.com/v2/synced-folders/index.html).


Install
-------

```
$ git clone https://github.com/chrisfarms/nixos-shell.git
$ cd nixos-shell
$ nix-env -i -f default.nix
```

If you want your containers to be able to connect to the internet you will need
to setup NAT on your host by adding something like the following to your
config:

```
networking.nat = {
	enable = true;
	externalInterface = "eth0";
	internalInterfaces = [ "ve-+" ];                                                                                            
};
```

FAQ
---

####What's a configuration.nix file
See the [NixOS manual](http://nixos.org/nixos/manual/#ch-configuration).

####Isn't this just nix-shell?
No. `nix-shell` will drop you into a chroot, with any required build
dependencies, but won't handle dependent *services*. `nixos-shell` will 
drop you into a *containter* which is closer to booting a virtual machine
with everything you need.

####Isn't this just nixos-container?
Not quite. `nixos-shell` builds on tops of `nixos-container` to spawn 
a temporary environment. That is, it sets up your environment, gets you 
logged in, then takes care of tearing it up and tidying up after you when 
you log out.




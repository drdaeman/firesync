# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  # For a reference, please see the online documentation at
  # https://docs.vagrantup.com.

  config.vm.box = "ubuntu/trusty32"
  config.vm.network "forwarded_port", guest: 8000, host: 8000

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y python-pip python3-pip python-virtualenv python-m2crypto \
        python-dev python3-dev libssl-dev swig

    virtualenv --system-site-packages ~/virtualenv
    ~/virtualenv/bin/pip install -r /vagrant/requirements.txt
    [ -d ~/bin ] || mkdir ~/bin
    [ -e ~/bin/python ] || ln -s ~/virtualenv/bin/python ~/bin/python

    virtualenv --system-site-packages -p $(which python3) ~/virtualenv3
    ~/virtualenv3/bin/pip install -r /vagrant/requirements.txt
    [ -e ~/bin/python3 ] || ln -s ~/virtualenv3/bin/python ~/bin/python3
  SHELL
end

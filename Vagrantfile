# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  # For a reference, please see the online documentation at
  # https://docs.vagrantup.com.

  config.vm.box = "ubuntu/trusty32"
  config.vm.network "forwarded_port", guest: 8000, host: 8000

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y python-pip python-virtualenv python-m2crypto
    virtualenv --system-site-packages ~/virtualenv
    ~/virtualenv/bin/pip install -r /vagrant/requirements.txt
    [ -d ~/bin ] || mkdir ~/bin
    [ -e ~/bin/python ] || ln -s ~/virtualenv/bin/python ~/bin/python
  SHELL
end

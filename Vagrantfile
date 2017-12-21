Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.provision :shell, path: "vagrant_bootstrap.sh"

  # Required for NFS to work, pick any local IP
  config.vm.network :private_network, ip: '192.168.50.50'

  # Use NFS for shared folders for better performance
  config.vm.synced_folder '.', '/vagrant', nfs: true
end

# Chroot Guide
Chroot with directories that is not owned by root and you cannot change the state of things.

1. Create the user.
useradd user

2. Modify `/etc/passwd` to negate interactive shell for user. (Optional: Added security)
user:x:1068:1069::/home/user:/sbin/nologin

4. Create directories for chroot.
mkdir /chroot/user # The chroot directory
mkdir /chroot/user/efs # The directory for binding other directories
mkdir /chroot/user/owned-by-other-user # The directory for binding other directories

5. Modify `/etc/ssh/sshd_config`
Match User user
   ChrootDirectory /chroot/user
   ForceCommand internal-sftp
   X11Forwarding no
   AllowTcpForwarding no

<make other necessary changes if required>

6. Make the user login passwordless.
# Paste the user's pub key in /home/user/.authorized_keys

Chmod /home/user/.ssh/ files in the accessing server to comply with chroot-sshd rules.
600 authorized_keys
600 id_rsa
700 id_rsa.pub

7. Accessing a non-root-owned directories (such as efs and other dirs) to user.
mount --bind /owned-by-root/dir /chroot/user/efs
mount --bind /owned-by-other-user/dir /chroot/user/owned-by-other-user

Example: 
mount --bind /appl/di_shareddata/arrow_sftp/thakral /chroot/user/efs

# to remove the binds
umount /home/test_sftp

8. (Optional) Incase for a restart, run to mount automatically:
echo '/owned-by-root/dir /home/test_sftp	none	bind' >> /etc/fstab

Notes:
* SSHD checks for authorized keys before it chroots, so it needs to find them using an un-chrooted path.
* All directories present in /etc/passwd must be un-chrooted.
* The chroot directory and all of its parents must not have group or world write capabilities (ie chmod 755)
* The chroot directory and all of its parents must be owned by root.

Example:
ChrootDirectory directory must be owned by root and have 755 mode:
sudo chown root:root /chroot/user/
sudo chmod 755 /chroot/user/

* You can bind multiple directories to the created directory: `/chroot/user/efs` or `/chroot/user/owned-by-other-user`
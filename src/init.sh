#!/bin/sh -ex
# mostly stolen from https://gist.github.com/jumanjiman/f9d3db977846c163df12

# remove unused users
sed -i -r '/^(root|shadow|sshd)/!d' /etc/group
sed -i -r '/^(root|shadow|sshd)/!d' /etc/passwd
sed -i -r '/^(root|shadow|sshd)/!d' /etc/shadow

# symlink to /run for config generation
ln -svf /run/msmtprc /etc/msmtprc
ln -svf /run/sshd.pam /etc/pam.d/sshd
ln -svf /usr/sbin/sshd.pam /usr/sbin/sshd
ln -svfb /run/group /etc/group
ln -svfb /run/passwd /etc/passwd
ln -svfb /run/shadow /etc/shadow

rm -Rf \
/etc/acpi \
/etc/conf.d \
/etc/crontabs \
/etc/environment \
/etc/fstab \
/etc/init.d \
/etc/inittab \
/etc/logrotate.d \
/etc/mdev.conf \
/etc/modprobe.d \
/etc/modules \
/etc/motd \
/etc/periodic \
/etc/profile \
/etc/profile.d \
/etc/protocols \
/etc/rc.conf \
/etc/runlevels \
/etc/services \
/etc/shells \
/etc/ssh/ssh*_config \
/etc/ssl* \
/etc/sysctl* \
/etc/terminfo \
/lib/rc \
/media \
/usr/share \
/var/spool/cron

find / -xdev -type d -perm +0002 -exec chmod o-w {} + # remove world-writable
find / -xdev -type f -perm +0002 -exec chmod o-w {} + # remove world-writable

sysdirs="
  /bin
  /etc
  /lib
  /sbin
  /usr
"
find $sysdirs -xdev -type f -a -perm +4000 -delete # remove suid files.
find $sysdirs -xdev -regex '.*apk.*' -exec rm -fr {} + # remove apk

# vacuum empty dirs, should have no security benefit but looks nice
find / \
  -depth \
  -empty \
  -not -path "/dev/*" \
  -not -path "/proc/*" \
  -not -path "/run/lock/*" \
  -not -path "/sys/*" \
  -not -path "/var/empty*" \
  -type d \
  -delete

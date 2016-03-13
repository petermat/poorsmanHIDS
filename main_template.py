#!/usr/bin/env python
 
'''
 
_   _           _     _____            _              
| | | |         | |   /  ___|          | |            
| |_| | __ _ ___| |__ \ `--.  ___ _ __ | |_ _ __ _   _
|  _  |/ _` / __| '_ \ `--. \/ _ \ '_ \| __| '__| | | |
| | | | (_| \__ \ | | /\__/ /  __/ | | | |_| |  | |_| |
\_| |_/\__,_|___/_| |_\____/ \___|_| |_|\__|_|   \__, |
                                                 __/ |
Tiny Host-Based IDS for the poor & lazy          |___/
 
                                                Martin Obiols
                                                http://blog.makensi.es
                                                @olemoudi
 
Remotely monitor server installations for file changes and/or file creations.
Useful for monitoring binaries and scripts and warn about unauthorized
modifications or uploads. Just read the prerequisites and edit the basic
options below.
 
what this script does:
   1- mounts remote dirs using sshfs
   2- checks their hashes
   3- alerts of changes
 
 
Prerequisites on the machine running the script:
 
1- sudo apt-get install ssh sshfs md5deep fuse-utils
   commands used by the script look like:
       $ sshfs user@host:/dir /mountpoint -p 22
       $ md5deep -r /mountpoint/file
       $ fusermount -u /mountpoint
   ensure they are available, you may need to also do:
       # chmod g+rw /dev/fuse
       # usermod -a -G fuse yourusername
2- Generate your RSA keys: $ ssh-keygen
3- Grant login without passwords: $ ssh-copy-id user@host_to_monitor
   Test it is indeed working, $ ssh user@host_to_monitor
4- Edit parameters below
5- Install as a cron job or whatever
 
Prerequisites on the machine to be monitored:
 
1- A working SSH server
 
 
Known caveats:
 
- Be conservative in the number (and size) of the files you monitor. Remember
 you are computing hashes across the network.
- Maximum number of files that can be monitored: getconf ARG_MAX (usually ~2M)
- Upon rightful file modifications, hash file must be deleted and recreated
 to avoid false alerts. (Or manual edit of the hash file).
 Default location: ~/.hashsentry/hostname.hash
 
'''
 
 
#################
# BASIC OPTIONS #
#################
 
#########################################################
# Host specification                                    #
#                                                       #
# Connection parameters for SSH.                        #
# Use localhost for local monitoring                    #
#########################################################
host = 'localhost'
user = 'ole'
port = 22
 
#########################################################
# Directories to monitor                                #
#                                                       #
# List of dir pathnames (NOT FILES) to monitor          #
# recursively. Files within these root directories will #
# be monitored for checksum changes and new unknown     #
# files created inside will be reported.                #
# Example:                                              #
# monitor_dirs = [ '/var/www', '/etc', '/bin' ]         #
#########################################################
monitor_dirs = [
        '/usr/share/wordpress/'
]
 
#########################################################
# Paths to exclude                                      #
#                                                       #
# List of absolute pathnames to exclude from monitoring #
# Wildcards can be used. Matching is case insensitive   #
# Example:                                              #
# excludes = [ '/var/www/uploads/', '*.png' ]           #
# will exclude:                                         #
#       - Everything under /var/www/uploads             #
#       - Files with png extension anywhere             #
#########################################################
excludes = [
    '/usr/share/wordpress/wp-content/uploads/'
]
 
#########################################################
# Alert by Email                                        #
#                                                       #
# Set to False if you wish HashSentry to just report to #
# stdout                                         .      #
#########################################################
send_emails = True
 
#########################################################
# Emails to notify                                      #
#                                                       #
# List of emails that will receive the reports.         #
# Localhost SMTP will be used by default.               #
# Example:                                              #
# alert_emails = [ 'joe@foo.com', 'june@bar.com' ]      #
#########################################################
alert_emails = ['']
 
 
#########################################################
#########################################################
# Most people won't need to scroll beyond here          #
#########################################################
#########################################################
 
 
####################
# ADVANCED OPTIONS #
####################
 
#########################################################
# Hash Algorithm                                        #
#                                                       #
# Available hashes: md5, sha1, sha256, tiger, whirlpool #
#########################################################
HASH = 'md5'
 
#########################################################
# Working Directory                                     #
#                                                       #
# Hashes will be stored in this local directory         #
# Default: ~/.hashsentry                                #
#########################################################
from os import path
WORK_DIR = path.join(path.expanduser('~'), '.hashsentry')
 
#########################################################
# SMTP                                                  #
#                                                       #
# Mail Transfer Agent host for email alerts.            #
#########################################################
SMTP = 'localhost'
EMAIL_FROM = 'HashSentry <hashsentry@localhost>'
 
#########################################################
# Alert only Flag                                       #
#                                                       #
# Set to False if you wish HashSentry to send reports   #
# even when everything is OK                     .      #
#########################################################
ALERT_ONLY = True
 
#########################################################
# File size threshold                                   #
#                                                       #
# Only files smaller than given threshold will be       #
# hashed.                                               #
# Available multipliers: b, k, m, g, t, p               #
#########################################################
MAX_FILESIZE = '100m'
 
#########################################################
#########################################################
#########################################################
#########################################################
#########################################################
 
VERSION = "0.1"
 
import sys
import subprocess
import os
import tempfile
import smtplib
import shlex
import fnmatch
import re
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
 
def sendMail(fro, to, subject, text, files=[], server="localhost"):
 
    msg = MIMEMultipart()
    msg['From'] = fro
    msg['To'] = COMMASPACE.join(to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
 
    msg.attach(MIMEText(text))
 
    for file in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(file, "rb").read())
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % \
                                                        os.path.basename(file))
        msg.attach(part)
 
    smtp = smtplib.SMTP(server)
    smtp.sendmail(fro, to, msg.as_string())
    smtp.close()  
 
 
 
if __name__ == '__main__':
 
    log = []
    log.append("This is HashSentry v%s" % VERSION)
    log.append('Checking files on %s' % host)
 
    alert = False
 
    # Check enviroment
    dbpresent = True
    if not os.path.exists(WORK_DIR):
        os.makedirs(WORK_DIR)
        dbpresent = False
        log.append('Creating %s' % WORK_DIR)
 
    hashes = os.path.join(WORK_DIR, host + '.' + HASH)
    if not os.path.exists(hashes):
        log.append('Unable to find hashes file %s' % hashes)
        log.append('A new file will be created')
        dbpresent = False
 
    temp_dirs = {}    
 
    # mount sshfs
    port = 22 if port == None else port
 
    for target_dir in monitor_dirs:
 
        target_dir = os.path.normpath(target_dir)
        # create a temporary dir as mount point
        temp_dir = tempfile.mkdtemp()
        mount_cmd = "sshfs %s@%s:%s %s -p %i -o reconnect,follow_symlinks" % \
                                     (user, host, target_dir, temp_dir, port)
 
        # mount dirs
        try:
            # be sure to always enforce shell=False to avoid injection attacks
            retcode = subprocess.call(shlex.split(mount_cmd), shell=False)
 
            if retcode != 0:
                log.append("Error while mounting (%i): %s" \
                % (retcode, mount_cmd))
                alert = True
            else:
                log.append('Successfully mounted %s@%s:%i:%s -> %s' % \
                                         (user, host, port, target_dir, temp_dir))
           
            temp_dirs[temp_dir] = target_dir
            # translate excludes for new mount point
            excludes = [i.replace(target_dir, temp_dir) for i in excludes]
 
        except Exception as e:
            log.append("sshfs mount failed: %s" % mount_cmd)
            log.append(str(e))
            alert = True
 
 
    # compile regex for exclusion list
    excludes = excludes if len(excludes) >= 1 else ['']
    excl_regex = '|'.join([fnmatch.translate(x) for x in excludes])
    excl_regex += '(?i)' #ignore case
   
    filelist = []
 
    for temp_dir in temp_dirs:
 
        for root, dirs, files in os.walk(temp_dir):
 
            files = [os.path.join(root, f) for f in files]
            #filenames with spaces need escaping
            files = [f.replace(" ","\ ") \
                                for f in files if not re.match(excl_regex, f)]
            filelist.extend(files)
 
    args = " ".join(filelist)
    if len(args) == 0:
        alert = True
        log.append('File list is empty, check your exclusion paths')
        log.append('Did the mount commands succeeded? connection error?')
 
    # compute hashes
 
    else:
        '''
       hashdeep options are:
           -t Display a timestamp in GMT with  each  result
           -z Enables file size mode. Prepends the hash with a ten digit
              representation of the size of each file processed
           -i Size threshold mode. Only hash files smaller than the  given
              threshold
           -X Negative matching, only files not in the list will be displayed
           -r Recursive mode
       '''
 
        if (dbpresent):
            cmd = '%sdeep -tz -X %s -i %s -r %s' % \
                                (HASH, hashes, MAX_FILESIZE, args)
        else:
            cmd = '%sdeep -tz -i %s -r %s' % (HASH, MAX_FILESIZE, args)
 
        try:
            p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)    
            output = p.stdout.read()
            p.wait()
            # translate pathnames
            for temp_dir in temp_dirs:
                output = output.replace(temp_dir, temp_dirs[temp_dir])        
 
            if not dbpresent:
                # create new hash file
                f = open(hashes, 'w')
                f.write(output)
                f.close()
                log.append('Hashes file successfully created: %s' % hashes)
            else:
                if len(output) == 0: # success
                    log.append('No hash changes or unknown files')
                else: # unmatched inputs
                    s = '''
\t___###____##_______########_########__########_
\t__##_##___##_______##_______##_____##____##____
\t_##___##__##_______##_______##_____##____##____
\t##_____##_##_______######___########_____##____
\t#########_##_______##_______##___##______##____
\t##_____##_##_______##_______##____##_____##____
\t##_____##_########_########_##_____##____##_
'''                
                    log.append(s)
                    log.append('')
                    log.append(
                    'The following files did not match any of the registered hashes:'
                    )
                    log.append('')
                    log.append(output)
 
                    alert = True
 
        except Exception as e:
            log.append("execution failed: %s" % (cmd))
            log.append(str(e))
 
 
    # housekeeping, unmount sshfs
 
    for temp_dir in temp_dirs:
        unmount_cmd = "fusermount -u %s" % temp_dir
        try:
            # be sure to always enforce shell=False to avoid injection attacks
            retcode = subprocess.call(shlex.split(unmount_cmd), shell=False)
 
            if retcode != 0:
                log.append("Error while unmounting (%i): %s"
                % (retcode, unmount_cmd))
            else:
                log.append("Successfully unmounted %s" % temp_dir)
           
        except Exception as e:
            log.append("sshfs unmount failed: %s" % unmount_cmd)
            log.append(str(e))
           
    # send alerts
 
    report = "\n".join(log)
 
    if alert or not ALERT_ONLY:
 
        if send_emails:
            log.append('Sending emails...')
            subject = "HashSentry Report for %s - OK Status" % \
                                        host if not alert else \
                "HashSentry ALERT for %s" % host
            sendMail(EMAIL_FROM, alert_emails, subject, report, server=SMTP)
            log.append('OK')
 
    print("\n".join(log)) # always report to stdout

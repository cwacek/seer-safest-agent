# Copyright (C) 2009 SPARTA, Inc.
# This software is licensed under the GPLv3 license, included in
# ./GPLv3-LICENSE.txt in the source distribution
#
#  Modifications by Chris Wacek (SAFER/SAFEST) <cwacek@cs.georgetown.edu>
#   * Oct. 2011 - Modified to use curl for web fetches
#               - Now capable of specifying location for logging output.
#                 This required overwriting some of the inherited code.
#

from util.platform import spawn
from util.cidr import CIDR
from subprocess import Popen,call,check_call
from backend.agent import Agent, AddressPool
from backend.variables import *
from backend.addon import services
import logging
import signal
import apt
import sys
import os
import time

def writeout(f,msg):
        f.write("%s\n" % msg)
        f.flush()

class SocksHTTPAgent(Agent):
    """
    This HTTP generator controls a set of clients that make HTTP requests to a set of servers running apache through a SOCKS proxy.
    """
    
    DEPENDS = ['ApacheService']
    SOFTWARE = ['curl']

    AGENTGROUP = 'Traffic'
    AGENTTYPE = 'Socks HTTP'
    NICENAME = 'Proxied Web'
    COMMANDS = ['START','STOP']
    VARIABLES = [
        Title('Web Settings'),
        NodeListVar('clients', None, 'Clients', 'Select the nodes that will become HTTP agents'),
        NodeListVar('servers', None, 'Servers', 'Select the nodes that will become HTTP servers'),
        StringVar('socks_addr','localhost:9050','Socks Proxy Address', 'The address and port of the SOCKS proxy to use'),
        DistVar('think', 1, 'Thinking Time', 'Function to determine time between requests'),
        DistVar('sizes', 1, 'File Sizes', 'Function to determine the size of the page requested'),
        StringVar('logpath',None,'Log Path', "The directory to log output to")
        ]

    def install_packages(self, names):
        """Use python-apt to install a list of packages, such as tor"""
        # THIS ONLY WORKS ON UBUNTU
        
        self.log.info("Install packages")
        
        cache = apt.Cache()
        
        self.log.info("Updating apt cache")

        try:
            cache.update()
        except Exception as e:
            self.log.info("Failed to update the apt cache: %s" % str(e))
            self.log.info("Are you running as root?")

        cache.open(None)

        self.log.info("Marking packages")

        for name in names:
            try:
                pkg = cache[name]
                
                if not pkg.is_installed:
                    self.log.info("Marking %s for installation" % name)
                    pkg.mark_install()

            except Exception as e:
                self.log.info("Problem looking up or marking %s for installation: %s" % (name, str(e)))

        self.log.info("Installing packages...")

        try:
            cache.commit()
        except Exception as e:
            self.log.info("Failed to install packages: %s" % str(e))
            self.log.info("Are you running as root?")
                       

    def __init__(self): Agent.__init__(self)

    handleSTOP = Agent.TGStop
    def serverExec(self): services.ApacheService.start()
    def serverStop(self): services.ApacheService.stop()

    def handleSTART(self):
        self.install_packages(['curl'])
        
        if self.logpath:
            try:
                os.makedirs(self.logpath)
            except OSError:
                pass

            self.logfilename = "%s/%s.curl.log" %(self.logpath, testbed.getNodeName())
            try:
                os.remove(self.logfilename)
            except:
                pass
        self.log.info("Calling self.TGStart()")
        self.TGStart()

    def clientExec(self, src, dst, size):
        self.log.info("Starting")

        ip_regex = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_regex.match(dst) is None:
            dst2 = testbed.getIPForNode(dst)
            #dst2 = "%s.%s.%s" % (dst, testbed.getExperiment(), testbed.getProject())
            dst = dst2[0]

        self.log.info("Chose to download from %s" % dst)

        url = "http://%s/getsize.py?length=%d " % (dst, size)
        logstring = "%s %%{time_connect} TTFB: %%{time_starttransfer} Total time: %%{time_total} Size: %%{size_download}\\n" % int(time.time())
        cmd = ['/usr/bin/curl', '--socks4', self.socks_addr, '-o','/dev/null','-w',logstring,url] 
        # We print this on stdout so it goes with redirected stdout
        self.log.info("Calling %s" % " ".join(cmd))
        try:
            ret = call(cmd)
        except Exception as e:
            if e[0] is not 10:
                self.log.info("calling curl failed: %s" % e)
            return
        self.log.info("Curl finished with code %s" %ret)
        #subpid = spawn(cmd, self.log.info)
   
    def TGStart(self): 
        if len(self.pids) > 0:
            self.log.info("Already running, not restarting")
            return
        
        if not self.servers and not self.clients:
            self.log.info("Uh, you need to give me something to run with. No clients and no servers?!?")
            return

        if (self.servers and self.servers.myNodeMemberOf()):
            self.log.info("Starting server")
            self.runningserver = 1
            self.serverExec()
            return

        if self.clients and self.clients.myNodeMemberOf():
            self.log.info("Starting client")
            self.launchTrafficController()
            return

        self.log.info("I am not one of clients or servers, so I'm doing nothing.")

    


    def launchTrafficController(self):
        """
            The default launcher called from :meth:`TGStart`, it will fork off a new session leader process
            that uses the servers, think and sizes variables to launch clients.  It will call 
            :meth:`clientOneLoop` repeatedly to start client processes.  A simple implementation of
            :meth:`clientOneLoop` is already provided.
        """
        self.log.info("Launching Traffic Controller")
        pid = os.fork()
        if (pid > 0):
            self.log.info("Started child as %s" % pid)
            self.pids.append(pid)
            return
        
        fperr = open("/tmp/forked.err",'w')
        writeout(fperr,"Opened logfile for forked process\n")
        sys.stderr = fperr
        os.dup2(fperr.fileno(),2)

        try:
            os.setsid()
            writeout(fperr,"Forked child process as %s" % pid)
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    
            spool = AddressPool(testbed.nodename, services.RoutingService.getFake(testbed.nodename))
            dpool = AddressPool()
            if self.servers:
                for s in self.servers:
                    dst = testbed.getIPForNode(s)
                    self.log.info("Adding '%s' to the destination pool" % dst)
                    dpool.Set(s, [CIDR(inputstr=ip) for ip in dst])

            
            if not self.logfilename:
                logfile = "/local/logs/%s.%s" % (self.AGENTTYPE, self.group)
            else:
                logfile = self.logfilename

            starttime = time.time()
    
            # Redirect stdout for exec'd applications
            try:
                writeout(fperr,"starting launcher process at %d - logging output to %s\n" % (starttime, logfile))
                fp = open(logfile, 'a', 1)
                sys.stdout = fp   # For python prints from here on (not logging)
                os.dup2(fp.fileno(), 1)  # For anything we exec from here on
                sys.stdout.write("Redirected STDOUT effectively\n")
            except Exception:
                self.log.warn("Failed to redirect output", exc_info=1);
    
            # Call overridden init method
            self.clientInit() 
        
            # Loop based on wait times
            try:
                while (True):
                    """
                    if 'autoquit' in self.VARIABLES:
                        elapsed = time.time() - starttime;
                        if ((self.autoquit > 0) and (elapsed > self.autoquit)):
                            os.killpg(0, signal.SIGTERM) # This should kill me and my children as I forked/setsid()
                            return
                    """
        
                    self.clientOneLoop(spool, dpool, self.think, self.sizes)
    
            except Exception,e:
                writeout(fperr,"error in client process: %s"% e);
        except Exception,e:
            writeout(fperr,"Error: %s" % e)
        finally:
            os._exit(0) 


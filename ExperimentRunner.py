#!/usr/bin/env python
import sys
import logging
import pickle
import os
import time
import yaml
import signal
import cmd
sys.path.append('/usr/seer')  # Necessary if this is not already in your python path

from testbed import testbed
from app.logsetup import logSetup

#xrange() stops at 1 less than the second number, so this is 1-5
DIRECTORIES = [ "directory%i" % i for i in xrange(1,6)]
RELAYS = ["relay%i" % i for i in xrange(1,26)]
CLIENTS = ["client%i" % i for i in xrange(1,11)]

def bold(msg):
    return "\033[1m" + msg + "\033[0;0m"

class ExperimentConfig():
    REQUIRED_PROPS = ['num_dirs','num_relays','num_clients','template_dir',
                      'thinking_time','file_sizes','socks_address','num_servers',
                      'save_data_location']
    
    def __init__(self,filename):
        f = open(filename, 'r')
        self.conf = yaml.safe_load(f.read())

        for prop in ExperimentConfig.REQUIRED_PROPS:
            try:
                self.conf[prop]
            except KeyError as e:
                del self
                raise Exception("Experiment config file missing required property: %s" % e)

    def getProp(self,prop):
        if prop.find(":") is -1:
            return self.conf[prop]
        else:
            properties = prop.split(":")
            conf = self.conf
            for key in properties:
                conf = conf[key]
            return conf

    def setProp(self,prop,val):
        self.conf[prop] = val

    def __str__(self):
        return yaml.dump(self.conf)

#class ExperimentRunner(messaging,cmd.Cmd):
class ExperimentRunner(cmd.Cmd):
    """ A command line tool for running SAFEST-Tor experiments on DETER """

    prompt = bold("(Exp) ")
    STATUS_RUN = 1
    STATUS_WAIT = 2

    def do_getIP(self,arg):
        """Ask the testbed for this node's IP Address"""
        split = arg.split(None)
        testbed.getNodeIP(split[0],split[1])

    def do_quit(self,arg):
        """quit the program"""
        self.do_stop_current_experiment(None)
        sys.exit(0)

    def do_add(self,arg):
        """add <name> <configfile>
        Add the experiment represented by configfile, and save it as name"""

        if not arg :
            print "Missing arguments."
            return

        try:
            (name,exp_filename) = arg.split(None,2)
        except ValueError:
            print "Missing arguments."
            return
    
        if name is None or exp_filename is None:
            print "Missing arguments. %s" % self.do_addExperiment.__doc__
            return

        if name in self.experiments:
            print "'%s' already used as experiment name" % name
            return

        try:
            self.experiments[name] = ExperimentConfig(exp_filename)
            self.experiments[name].name = name
        except yaml.YAMLError, exc:
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                print "Error position: (%s:%s)" % (mark.line+1, mark.column+1)
            else:
                print "Error in config file:", exc
            return
        except Exception as e:
            print "Error %s" % e
            return

        print "Experiment '%s' added successfully" % name

    def do_list(self,arg=None):
        """list [exp] 
        - Print a list of the known experiments or the configuration for 'exp'"""
        
        if not arg:
            if len(self.experiments) == 0:
                print "No loaded experiments"
            else:
                print bold("Loaded Experiments:")
                print "\n".join(self.experiments)
                
        else:
            if arg in self.experiments: 
                print bold("'%s' Configuration" % arg)
                print self.experiments[arg]
            else:
                print "No experiment called '%s' exists" % arg

    def do_stop_current_experiment(self,exp):
        """ Stop a running experiment immediately. Do \033[1mNOT\033[0;0m save data"""

        if self.status is ExperimentRunner.STATUS_WAIT:
            print "No experiment currently running"
            return
        else:
            from backend.scriptbase import run
            run(self.stopExpImpl)
            
    def do_run(self,exp):
        """run <experiment_name> [<experiment_name ...]
        Run the experiment with the name <experiment_name>,
        or the list of experiments if applicable."""

        if self.status is ExperimentRunner.STATUS_RUN:
            print "Already running experiment '%s'" % self.running_exp
            return

        if not exp:
            print "Requires an experiment name to run"
            return

            
        for experiment_name in exp.split(' '):

            from backend.scriptbase import ScriptController
            try:
                expConf = self.experiments[experiment_name]
            except KeyError:
                print "No such experiment"
            else:
                try:
                    self.to_run = expConf;

                    ## NOTE
                    #  This is one of the kludgier things I have ever done.
                    #  All of the rest of this function was copied from backend/scriptbase.py
                    #  because the run function that gets imported otherwise calls sys.exit(0)
                    #  when it completes. This (obviously) precludes us from running a series
                    #  of experiments. 
                    #
                    #  Not exactly Object Orientation the way it was intended, but it works.
                    #
                    basename = os.path.basename(sys.argv[0][:-3])
                    signal.signal(signal.SIGINT, signal.SIG_DFL)
                    logSetup(basename, False)

                    # Use script name as node name and then start everything
                    messaging = ScriptController(basename, testbed.cafile, testbed.nodefile, self.runExpImpl)
                    messaging.loop()
                    # Messaging loop exists when stop is called or running = False
                    if messaging.started:
                        messaging.script.join()
                    self.log.info("Waiting 15 minutes before starting the next experiment to allow out of band things to finish (e.g. copying data).")
                    time.sleep(900)
                except Exception as e:
                    print "Unknown Error: %s" % e

    def do_status(self,arg):
        """Show the status of this ExperimentRunner instance"""
        if self.status == ExperimentRunner.STATUS_RUN:
            print "Currently running '%s" % self.running_exp
        else:
            print "No activity"

    def runExpImpl(self,messaging):
        """Run the experiment currently configured to run"""
        
        try:
            self.torGroup = messaging.newGroup('TOR','Tor_%s' % self.to_run.name)
            self.log.info("Tor Group established")
            self.webGroup = messaging.newGroup('Socks HTTP',"Web_%s" % self.to_run.name)
            self.log.info("Web Group established")
            if self.to_run.getProp('use_tcp_app') is not None:
                self.tcpGroup = messaging.newGroup("Socks Application", "Web_%s" % self.to_run.name)
            else:
                self.tcpGroup = None
            self.setupExp(self.to_run)
            self.log.info("Experiment set up.")
        except Exception as e:
            self.log.debug("Encountered unknown error: %s" % e)

        try:
            self.status = ExperimentRunner.STATUS_RUN
            self.running_exp = self.to_run

            self.log.debug("Sending RM_CACHE")
            self.stopExpImpl(cleanup=True)
            self.log.debug("Sending START to Tor")
            self.torGroup.START()
            time.sleep(900)
            self.log.debug("Sending START to Web")
            self.webGroup.START()
            if self.tcpGroup:
                self.tcpGroup.START()
            self.log.debug("Letting it run for 9000 seconds")
            time.sleep(9000)
            self.log.debug("Stopping everything")
            self.stopExpImpl()
            self.log.debug("Stopped. Saving Data")
            self.torGroup.SAVE_DATA()
            self.log.debug("Data Saved")
            self.running_exp = None
            self.status = ExperimentRunner.STATUS_WAIT
        except Exception as e:
            self.log.debug("Error: %s" % e)


    def stopExpImpl(self,cleanup=False):
        self.webGroup.STOP()
        self.torGroup.STOP()
        if self.tcpGroup:
            self.tcpGroup.STOP()
        self.torGroup.KILL()
        if cleanup is True:
            self.torGroup.RM_CACHE()
        self.log.debug( "Sent STOP command to web and Tor groups")

    def complete_load(self, text, line, begidx, endidx):

        if text is None:
            completions = os.listdir(".")
        else:
            path = text.split('/')

            try:
                if len(path) == 1:
                    completions = [ f for f in os.listdir(".") if f.startswith(text)]
                else:
                    searchpath = "/".join(path[:-1])
                    self.log.debug("Searching at %s" % searchpath)
                    completions = [ "%s/%s" % (searchpath,f) 
                                    for f in os.listdir("./%s/" % searchpath) 
                                    if f.startswith(path[-1])]
            except Exception as e:
                print "Error: %s" % e

        return completions

    def setupExp(self,expConf):
        """Prepare to run the experiment expConf"""
        try:
            dirs = [ "directory%i" % i for i in xrange(1,expConf.getProp('num_dirs')+1)]  
            relays = ["router%i" % i for i in xrange(1,expConf.getProp('num_relays')+1)]    
            clients = ["client%i" % i for i in xrange(1,expConf.getProp('num_clients')+1)] 
            servers = ["server%i" % i for i in xrange(1,expConf.getProp('num_servers')+1)] 

            self.torGroup.directory = ",".join(dirs)
            self.torGroup.relays = ",".join(relays)
            self.torGroup.clients = ",".join(clients)

            self.torGroup.template_dir = expConf.getProp('template_dir')
            self.torGroup.tor_binary = expConf.getProp('tor_binary')
            self.torGroup.save_data_dir = expConf.getProp('save_data_location')
            self.torGroup.client_config_list = ",".join(expConf.getProp('client_config_options'))
            self.torGroup.relay_config_list = ",".join(expConf.getProp('relay_config_options'))

            self.webGroup.clients = ",".join(clients)
            self.webGroup.servers = ",".join(servers)
            self.webGroup.socks_addr = expConf.getProp('socks_address')
            self.webGroup.logpath = '/var/lib/tor/'
            self.webGroup.think = expConf.getProp('thinking_time')
            self.webGroup.sizes = expConf.getProp('file_sizes')

            if self.tcpGroup is not None:
                self.tcpGroup.clients = ",".join(clients)
                self.tcpGroup.servers = ",".join(servers)
                self.tcpGroup.socks_addr = expConf.getProp('socks_address')
                self.tcpGroup.logpath = '/var/lib/tor/'
                self.tcpGroup.think = expConf.getProp('use_tcp_app:thinking_time') 
                self.tcpGroup.server_cmd = expConf.getProp("use_tcp_app:server_cmd")
                self.tcpGroup.app_cmd = expConf.getProp("use_tcp_app:client_cmd")


        except Exception as e:
            print "Error: %s" % e

    def do_save(self,arg):
        """save <path>
        save the current configuration from <path>"""
                  
        if not arg:
            print "Need a pathname to save to"
            return

        args = arg.split(None)
        if os.path.exists(args[0]):
            print "%s already exists. Will not overwrite"
            return 

        curr = self.running_exp if hasattr(self,'running_exp') else None
        pickle.dump((self.experiments,self.status,curr),open(args[0],'wb'),-1)

    def do_load(self,arg):
        """load <path> 
        Load a saved configuration from <path>"""

        if not arg:
            print "need a path to load from"
            return

        args = arg.split(None)
        if not os.path.exists(args[0]):
            print "%s is not a valid path to load from " % args[0]
            return

        try:
            (self.experiments,self.status,self.running_exp) = pickle.load(open(args[0], 'rb'))
        except Exception as e:
            print "Error Loading file: %s" % e 
            return

    def __handle_term(self):
        self.do_quit(list())

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.experiments = dict()
        self.log = logging.getLogger("ExperimentRunner")
        self.log.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s') 
        sh = logging.StreamHandler()
        fh = logging.FileHandler('ExperimentRunner.log',mode='w')                    
        fh.setFormatter(fmt)
        sh.setFormatter(fmt)
        self.log.addHandler(fh)
        self.log.addHandler(sh)
        self.status =  ExperimentRunner.STATUS_WAIT


signal.signal(signal.SIGTERM,signal.SIG_IGN)
if __name__ == '__main__':
    if os.getuid() != 0:
        sys.stderr.write("Need to be run as root\n")
        sys.exit(-1)

    ER = ExperimentRunner()

    while True:
        try:
            ER.cmdloop()
        except KeyboardInterrupt:
            print "Use the 'quit' command to exit"
            pass
        except Exception as e:
            ER.log.debug("Error: %s" % e)



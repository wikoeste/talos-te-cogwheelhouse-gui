import logging, os

def log(msg):
    homedir = os.path.expanduser("~")              # users home directory
    logdir  = homedir+"/logs"                      # path to logs directory
    # create logs dir if needed skip if present
    try:
        os.mkdir(logdir)
    except FileExistsError:
        pass
    fname   = logdir+'/te1-webapp.log'              # path to file name of the log
    # Create logger
    logging.basicConfig(
        format='%(asctime)s:%(name)s:%(levelname)s - %(message)s',
        level=logging.INFO,
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=fname )
    # Test log line
    logging.info(f"Logging initialized. Logs are saving to: {fname}")
    logging.error(msg)
"""
Test validity of a YAML file and print out resulting dictionary

Pass it a full path to a YAML file on command line, i.e.:

python yamltest.py /home/bob/nmeta/config/examples/tc_policy.yaml.nested-1
"""

#*** YAML for config and policy file parsing:
import yaml

import sys
import os

yaml_filename = sys.argv[1]

#*** Ingest the YAML file:
try:
    with open(yaml_filename, 'r') as filename:
        yaml_dict = yaml.load(filename)
except (IOError, OSError) as exception:
    print "ERROR: Failed to YAML file %s " % yaml_filename
    print "Exception is %s" % exception
    sys.exit("Exiting...")
print "\nSuccess! This is a valid YAML file\n"
print "YAML Dictionary:"
print "---------------\n"
print yaml_dict
print "\nHuman-Friendly Output:"
print "---------------------\n"
print yaml.dump(yaml_dict, default_flow_style=False)

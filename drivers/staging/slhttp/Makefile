# This rule extracts the directory part from the location where this Makefile
# is found, strips last slash and retrieves the last component which is used
# to make a file name. It is a generic way of building modules which always
# have the name of the directory they're located in. $(lastword) could have
# been used instead of $(word $(words)) but it's bogus on some versions.

obj-m += $(notdir $(patsubst %/,%,$(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))))).o

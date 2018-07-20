#!/bin/sh

# preserve old behavior of using an arg as a regex when '--' is not present
case $@ in
    (*--*) stestr run $@;;
    ('') stestr run;;
    (*) stestr run --regex "$@"
esac

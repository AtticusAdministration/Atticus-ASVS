#! /bin/bash

case $ASVS_VERSION in
  4.0)
    ./generate-all.sh
    ;;
  *)
    make $FORMATS
    make clean
    ;;
esac

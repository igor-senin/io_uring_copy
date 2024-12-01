#!/usr/bin/env bash

if [ $# -lt 1 ]
then
  echo "Usage: ${0} <file_name>"
  exit 1
fi

SOURCE_FILE="${1}"

if [ $# -eq 2 ]
then
  BIN_OUT="${2}"
else
  BIN_OUT="my_cp"
fi

gcc -luring -Wall -Wextra -I. -fsanitize=leak ${SOURCE_FILE} -o ${BIN_OUT}

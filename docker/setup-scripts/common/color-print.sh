#!/usr/bin/env bash

set -u
set -o pipefail

colored_echo() {
    # check color support
    local show_color=false
    if test -t 1 && which tput > /dev/null 2>&1; then
        # has terminal and tput, also check colors
        local colors=$(tput colors)
        if test -n "${colors}" && test "${colors}" -ge 8; then
            show_color=true
        fi
    fi

    # set color
    local color_set=true
    local color=0
    local color_code=${1:-}
    case "${color_code}" in
        black  | bk) color=0;;
        red    |  r) color=1;;
        green  |  g) color=2;;
        yellow |  y) color=3;;
        blue   |  b) color=4;;
        purple |  p) color=5;;
        cyan   |  c) color=6;;
        white  |  w) color=7;;
        *) color_set=false
    esac

    if [ "${color_set}" = true ]; then
        if [ "${show_color}" = true ]; then
            # color print
            tput setaf "${color}";
            echo "${@: 2}";
            tput sgr0;
        else
            # raw print without color param
            echo "${@: 2}";
        fi
    else
        # raw print
        echo "${@: 1}";
    fi
}

### test
# colored_echo 't1' 't2'
# colored_echo y 't1' 't2'
# colored_echo y 't1' 't2' > /tmp/tmp.txt; cat /tmp/tmp.txt
# colored_echo y 't1' 't2' | grep t

colored_cat() {
    # check color support
    local show_color=false
    if test -t 1 && which tput > /dev/null 2>&1; then
        # has terminal and tput, also check colors
        local colors=$(tput colors)
        if test -n "${colors}" && test "${colors}" -ge 8; then
            show_color=true
        fi
    fi

    # set color
    local color_set=true
    local color=0
    local color_code=${1:-}
    case "${color_code}" in
        black  | bk) color=0;;
        red    |  r) color=1;;
        green  |  g) color=2;;
        yellow |  y) color=3;;
        blue   |  b) color=4;;
        purple |  p) color=5;;
        cyan   |  c) color=6;;
        white  |  w) color=7;;
        *) color_set=false
    esac

    if [ "${color_set}" = true ] && [ "${show_color}" = true ]; then
        tput setaf "${color}";
        cat;
        tput sgr0;
    else
        cat;
    fi
}

### test
# echo 't1' 't2' | colored_cat
# echo 't1' 't2' | colored_cat r
# echo 't1' 't2' | colored_cat r > /tmp/tmp.txt; cat /tmp/tmp.txt
# echo 't1' 't2' | colored_cat r | grep t

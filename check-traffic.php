<?php
#
# Copyright (c) 2008 Michael Boehm (dudleyperkins)
# Plugin: check_cisco_traffic
# Last Modified: 2008-09-22
#
$opt[1] = "--lower=$MIN[1] --vertical-label \"Traffic \" --title \"Traffic usage for $hostname \" ";
#
#
#
$def[1] =  "DEF:traffic=$rrdfile:$DS[1]:AVERAGE " ;
$def[1] .= "DEF:In=$rrdfile:$DS[2]:AVERAGE " ;
$def[1] .= "DEF:Out=$rrdfile:$DS[3]:AVERAGE " ;
$def[1] .= "HRULE:$WARN[1]#FFFF00 ";
$def[1] .= "HRULE:$CRIT[1]#FF0000 ";

$def[1] .= "COMMENT:\"\\t\\t\\tLAST\\n\" " ;

$def[1] .= "AREA:In#006800:\"In\\t\t\":STACK " ;
$def[1] .= "GPRINT:In:LAST:\"%6.2lf MB\\n\" " ;

$def[1] .= "AREA:Out#00F000:\"Out\\t\t\":STACK " ;
$def[1] .= "GPRINT:Out:LAST:\"%6.2lf MB\\n\" " ;

$def[1] .= "COMMENT:\"Total\\t\t\" " ;
$def[1] .= "GPRINT:traffic:LAST:\"%6.2lf MB\\n\" " ;
?>


# Perl Module
# Purpose:  One Module to provide Syslog functionality
#           Provide log parser, sender, receiver
# Author    sparsons@cpan.org
#
# 

package Net::Dev::Tools::Syslog;

use strict;
use Time::Local;
use IO::Socket;
use Sys::Hostname;


BEGIN {
   use Exporter();
   our @ISA     = qw(Exporter);
   our $VERSION = 0.8.0;
}


#
# Tags
#
our @PARSER_func = qw(
   parse_syslog_msg
);

our @TIME_func = qw(
   epoch_to_timestamp
   make_timeslots
   epoch_timeslot_index
);

our @SYSLOG_func = qw(
   normalize_facility
   normalize_severity
   decode_PRI
);

our @REFERENCE_func = qw(
   data_aref
   stats_href
   device_aref
   facility_aref
   severity_aref
   tag_aref
   timeslot_aref
);




our @EXPORT = (@PARSER_func, @TIME_func, @SYSLOG_func, @REFERENCE_func);
our @EXPORT_OK  = qw();

our %EXPORT_TAGS = (
   parser  => [@PARSER_func],
   time    => [@TIME_func],
   syslog  => [@SYSLOG_func],
);
#
# Global variables
#
our $Syslog_LINE;
our $ERROR;
our $DEBUG;
our %FH;
our @DATA;
our %STATS;
our @DEVICES;
our @TAGS;
our @FACILITYS;
our @SEVERITYS;
our @TIMESLOTS;
our %LASTMSG;

our $YEAR = ((localtime)[5]) + 1900;

our %WDAY = (
      '0' => 'Sun',
      '1' => 'Mon',
      '2' => 'Tue',
      '3' => 'Wed',
      '4' => 'Thu',
      '5' => 'Fri',
      '6' => 'Sat',
);

our %MON = (
   1  => 'Jan',   2  => 'Feb',   3  => 'Mar',
   4  => 'Apr',   5  => 'May',   6  => 'Jun',
   7  => 'Jul',   8  => 'Aug',   9  => 'Sep',
   10  => 'Oct',  11 => 'Nov',   12 => 'Dec',
);


our %MON_index = (
   'JAN'  => 1,   'Jan'  => 1,  'jan'  => 1,
   'FEB'  => 2,   'Feb'  => 2,  'feb'  => 2,
   'MAR'  => 3,   'Mar'  => 3,  'mar'  => 3,
   'APR'  => 4,   'Apr'  => 4,  'apr'  => 4,
   'MAY'  => 5,   'May'  => 5,  'may'  => 5,
   'JUN'  => 6,   'Jun'  => 6,  'jun'  => 6,
   'JUL'  => 7,   'Jul'  => 7,  'jul'  => 7,
   'AUG'  => 8,   'Aug'  => 8,  'aug'  => 8,
   'SEP'  => 9,   'Sep'  => 9,  'sep'  => 9,
   'OCT'  => 10,  'Oct'  => 10, 'oct'  => 10,
   'NOV'  => 11,  'Nov'  => 11, 'nov'  => 11,
   'DEC'  => 12,  'Dec'  => 12, 'dec'  => 12,
);


our %Syslog_Facility = (
   'kern'     => 0,    'kernel' => 0,
   'user'     => 1,
   'mail'     => 2,
   'daemon'   => 3,
   'auth'     => 4,
   'syslog'   => 5,
   'lpr'      => 6,
   'news'     => 7,
   'uucp'     => 8,
   'cron'     => 9,
   'authpriv' => 10,
   'ftp'      => 11,
   'ntp'      => 12,
   'audit'    => 13,
   'alert'    => 14,
   'at'       => 15,
   'local0'   => 16,
   'local1'   => 17,
   'local2'   => 18,
   'local3'   => 19,
   'local4'   => 20,
   'local5'   => 21,
   'local6'   => 22,
   'local7'   => 23,
);


our %Facility_Index = (
   0   => 'kern',
   1   => 'user',
   2   => 'mail',
   3   => 'daemon',
   4   => 'auth',
   5   => 'syslog',
   6   => 'lpr',
   7   => 'news',
   8   => 'uucp',
   9   => 'cron',
   10  => 'authpriv',
   11  => 'ftp',
   12  => 'ntp',
   13  => 'audit',
   14  => 'alert',
   15  => 'at',
   16  => 'local0',
   17  => 'local1',
   18  => 'local2',
   19  => 'local3',
   20  => 'local4',
   21  => 'local5',
   22  => 'local6',
   23  => 'local7',
);

our %Severity_Index = (
   0  => 'emerg',
   1  => 'alert',
   2  => 'crit',
   3  => 'err',
   4  => 'warn',
   5  => 'notice',
   6  => 'info',
   7  => 'debug'
);




our %Syslog_Severity = (
   'emerg'   => 0,   'emergency' => 0,
   'alert'   => 1,
   'crit'    => 2,   'critical' => 2,
   'err'     => 3,   'error'    => 3,
   'warn'    => 4,   'warning'  => 4,
   'notice'  => 5,
   'info'    => 6,   'information' => 6,  'informational' => 6,
   'debug'   => 7,
);


our @FACILITY = qw( kern     user     mail      daemon
                    auth     syslog   lpr       news    
                    uucp     cron     authpriv  ftp
                    ntp      audit    alert     at
                    local0   local1   local2    local3
                    local4   local5   local6    local7
);
our @SEVERITY = qw( emerg alert crit err warn notice info debug);



our $SYSLOG_msg = '[JFMASONDjfmasond]\w\w {1,2}\d+ [0-9:]+ \S+ .+';



#
#=============================================================================
#
#                Methods and Functions
#
#
# Net::Dev::Tools::Syslog Constructor
#
# Use the anonymous hash to hold info for rest of module
#
# Arguments
#   dump        0|1   (0)  write to file
#   append      0|1    (1)  append to existing report
#   ext         extension  (.slp)
#   report      0|1  (1) create report
#   interval    report time slot interval
#   rx_time     0|1   determine if we should use msg time or preamble time
#   lastmsg     0|1   (0) do not use last message values
#   debug       0|1
#   filters
#     min_date         min date mm/dd/yyyy hh:mm:ss
#     min_date_epoch   filter_min_date => epoch 
#     max_date         max date mm/dd/yyyy hh:mm:ss
#     max_date_epoch   max_date => epoch
#     device
# 
sub parse {
   # create object
   my $proto = shift;
   my $class = ref($proto) || $proto;
   my $this  = {};
   # bless object
   bless($this, $class);

   # get object arguments
   my %arg = @_;
   my $a;

   $ERROR = '';
   @DATA = ();


   # define defaults
   $this->{ext}      = 'slp';
   $this->{dump}     = 0;      # default not to dump
   $this->{report}   = 1;      # default to report
   $this->{append}   = 0;      # default not to append
   $this->{interval} = 3600;   # default timeslot interval
   $this->{rx_time}  = 0;      # default to not use time stamp from preamble
   $this->{lastmsg}  = 0;      # default to not redo last message when 'last msg' line
   $this->{debug}    = 0;
   $this->{msg_plus} = 0;      # default to not grab extra info from message
   $this->{filter}   = 0;      # default no filtering
   
   foreach $a (keys %arg) {
      if    ($a =~ /^-?dump$/i)        {$this->{dump}       = delete($arg{$a}); }
      elsif ($a =~ /^-?append$/i)      {$this->{append}     = delete($arg{$a}); }
      elsif ($a =~ /^-?ext$/i)         {$this->{ext}        = delete($arg{$a}); }
      elsif ($a =~ /^-?report$/i)      {$this->{report}     = delete($arg{$a}); }
      elsif ($a =~ /^-?interval$/i)    {$this->{interval}   = delete($arg{$a}); }
      elsif ($a =~ /^-?rx_time$/i)     {$this->{rx_time}    = delete($arg{$a}); }
      elsif ($a =~ /^-?lastmsg$/i)     {$this->{lastmsg}    = delete($arg{$a}); }
      elsif ($a =~ /^-?debug$/i)       {$this->{debug}      = delete($arg{$a}); }
      elsif ($a =~ /^-?min_date$/i)    {$this->{filter_min_date}   = delete($arg{$a}); }
      elsif ($a =~ /^-?max_date$/i)    {$this->{filter_max_date}   = delete($arg{$a}); }
      elsif ($a =~ /^-?device$/i)      {$this->{filter_device}     = delete($arg{$a}); }
      elsif ($a =~ /^-?tag$/i)         {$this->{filter_tag}        = delete($arg{$a}); }
      elsif ($a =~ /^-?message$/i)     {$this->{filter_message}    = delete($arg{$a}); }
      else {
         $ERROR = "unsupported option  $a => $arg{$a}";
         return(wantarray ? (undef, $ERROR) : undef);
      }
   }
   # set globals
   $DEBUG = $this->{debug};


   #
   # check arguments
   #
   # if dump is enabled,
   if ($this->{dump}) {
         $this->{repository} = $this->{dump};
         # make sure we have trailing '/' or '\'
         if ($^O eq 'MSWin32') {
            if ($this->{repository} !~ /\\$/)
               {$this->{repository} = $this->{repository} . '\\';}
         }
         else {
            if ($this->{repository} !~ /\/$/)
               {$this->{repository} = $this->{repository} . '/';}
         }
         # check if writable
         if (!-w $this->{repository}) {
            $ERROR = "dump site not writeable";
            $this = undef;
            return(wantarray ? (undef, $ERROR) : undef);
         } 
   }
   #
   # interval can not be less than 1 min (60 sec), since the index
   # only goes down to the minute
   #
   if ($this->{interval} < 60) { 
      $this->{interval} = 60;
      log_debug(3, "NOTICE: interval changed to 60 seconds\n");
   }
   #
   # if we have any filters defined, then enable filtering
   #
   $this->{filter} = 1 if $this->{filter_min_date} || $this->{filter_max_date} ||
                          $this->{filter_device}   || $this->{filter_tag} ||
                          $this->{filter_message}; 
       
 

   # if we want to collect data, make sure we have a reference to a list
   if($this->{report}) { @DATA = ();}

   # check min and max date
   if ($this->{filter_min_date}) {
      log_debug(3, "convert min date: [%s]\n", $this->{filter_min_date});
      $this->{filter_min_date_epoch} = date_filter_to_epoch($this->{filter_min_date});
      unless($this->{filter_min_date_epoch}) {
         return(wantarray ? (undef, $ERROR) : undef);
      }
      log_debug(3, "converted min date to: [%s]\n", $this->{filter_min_date_epoch},
         epoch_to_datestr($this->{filter_min_date_epoch}),
      );
   }
   if ($this->{filter_max_date}) {
      log_debug(3, "convert max date: [%s]\n", $this->{filter_max_date});
      $this->{filter_max_date_epoch} = date_filter_to_epoch($this->{filter_max_date});
      unless($this->{filter_max_date_epoch}) {
         return(wantarray ? (undef, $ERROR) : undef);
      }
      log_debug(3, "converted max date to: [%s]\n", $this->{filter_max_date_epoch},
         epoch_to_datestr($this->{filter_max_date_epoch})
      );
   }

   if ($this->{filter_min_date} && $this->{filter_max_date}) {
      log_debug(3, "check min and max date range\n");
      if ($this->{filter_min_date_epoch} >= $this->{filter_max_date_epoch}) {
         $ERROR = sprintf("filter_min_date >= filter_max_date: %s >= %s", 
            commify($this->{filter_min_date_epoch}), 
            commify($this->{filter_max_date_epoch}),
         );
         log_debug(2, "%s\n", $ERROR);
         return(wantarray ? (undef, $ERROR) : undef);
      }
      log_debug(3, "min max date range: [%s] => [%s]\n",
         $this->{filter_min_date},  $this->{filter_max_date},
      );
      log_debug(3, "min max date range: [%s] => [%s]\n",
         commify($this->{filter_min_date_epoch}),  commify($this->{filter_max_date_epoch})
      ); 
   }

   if ($DEBUG) {
      foreach (sort keys %{$this}) {
         log_debug(2, "object properties: %s => %s\n", $_, $this->{$_});
      }
   }

 
   # return reference to object
   return(wantarray ? ($this, $ERROR) : $this);

}  # end sub parse
#
#.............................................................................
#
#  Function to parse syslog line and populate hash ref $Syslog_LINE
#
#     $Syslog_LINE->{line}      current line from syslog file
#                   {timestamp} timestamp from syslog message
#                   {device}    device name from syslog message
#                   {message}   syslog message, from after devname
#  
#                   {month_str} month from syslog message timestamp (Jan, Feb, ..) 
#                   {month}     month index 0->11
#                   {day}       day from syslog message timestamp
#                   {time_str}  hh:mm:ss from syslog message timestamp
#                   {hour}      hh from syslog message timestamp
#                   {min}       mm from syslog message timestamp
#                   {sec}       ss from syslog message timestamp
#                   {year}      year assumed from localtime
#                   {epoch}     epoch time converted from syslog message timestamp
#                   {wday}      wday integer derived from epoch (0-6) = (Sun-Sat)
#                   {wday_str}  wday string converted, (Sun, Mon, ...)
#                   {date_str}  syslog message {epoch} convert to common format
#
#                   {tag}       syslog message content tag
#                   {pid}       syslog message content tag pid
#                   {content}   syslog message content after tag parsed out
#
#                   {preamble}
#                   {rx_epoch}     extra info: rx time epoch
#                   {rx_timestamp} extra info: rx timestamp
#                   {rx_priority}  extra info: priority (text)
#                   {rx_facility}  extra info: syslog facility (text)
#                   {rx_severity}  extra info: syslog severity (text)
#                   {srcIP}        extra info: src IP address
#
#                   {rx_epoch}     extra info: rx time epoch
#                   {rx_date_str}  extra info: rx time date string
#                   {rx_time_str}  extra info: rx time (hh:mm:ss)
#                   {rx_year}      extra info: rx time year value
#                   {rx_month}     extra info: rx time month value
#                   {rx_month_str} extra info: rx time month value string (Jan, Feb,..)
#                   {rx_day}       extra info: rx time day value
#                   {rx_wday}      extra info: rx time weekday (0-6) (Sun, Mon,..)
#                   {rx_hour}      extra info: rx time hour value
#                   {rx_min}       extra info: rx time minute value
#                   {rx_sec}       extra info: rx time second value
# Arg
#   $_[0] - line from syslog file
#
sub parse_syslog_line {
   my $obj = shift;
   my $_line = shift || $_;

   my ($_preamble, $_msg, $_ok, $_last);
   my @_pre = ();

   $Syslog_LINE = {};
   $_line =~ s/\n$//;
   $Syslog_LINE->{line} = $_line;

   log_debug(1, "SYSLOG line:     [%s]\n", $_line);

   # if given line is blank ignore it, it will populate @DATA with an empty hash
   # which can throw off the stats
   if ($_line =~ /^\s*$/) {
      $ERROR = 'disregarding current line: blank line';
      return(wantarray ? (undef, $ERROR) : undef);
   }


   # see if we have more than just the syslog message
   if    ($_line =~ /(<\d{1,3}>)($SYSLOG_msg)/) {$_preamble = $1;    $_msg = $2}
   elsif ($_line =~ /(.+)\s+($SYSLOG_msg)/)     {$_preamble = $1;    $_msg = $2}
   elsif ($_line =~ /(.+),($SYSLOG_msg)/)       {$_preamble = $1;    $_msg = $2,  $_preamble =~ s/\,/ /g; }
   else                                         {$_preamble = undef; $_msg = $_line;}

   log_debug(2, "syslog preamble: %s\n", $_preamble || 'none');
   log_debug(2, "syslog message:  %s\n", $_msg      || 'NO MESSAGE');


   parse_syslog_msg($_msg, 1);
   if ($Syslog_LINE->{device} eq '') {
      $ERROR = 'no device name parsed from line'; 
      return(wantarray ? (undef, $ERROR) : undef);
   }


   # if we have a preamble, parse it out
   if ($_preamble) {
      $_preamble =~ s/UTC//;
      log_debug(2, "syslog line contains preamble:\n");
      # preamble:  yyyy-mm-dd hh:mm:ss prio ip
      parse_preamble($_preamble);
      # determine what time we want to keep
      if ($obj->{rx_time}) {
         $Syslog_LINE->{timestamp} = $Syslog_LINE->{rx_timestamp} || $Syslog_LINE->{timestamp};
         $Syslog_LINE->{epoch}     = $Syslog_LINE->{rx_epoch}     || $Syslog_LINE->{epoch};
         $Syslog_LINE->{month}     = $Syslog_LINE->{rx_month}     || $Syslog_LINE->{month};
         $Syslog_LINE->{month_str} = $Syslog_LINE->{rx_month_str} || $Syslog_LINE->{month_str}; 
         $Syslog_LINE->{day}       = $Syslog_LINE->{rx_day}       || $Syslog_LINE->{day};
         $Syslog_LINE->{time_str}  = $Syslog_LINE->{rx_time_str}  || $Syslog_LINE->{time_str};
         $Syslog_LINE->{hour}      = $Syslog_LINE->{rx_hour}      || $Syslog_LINE->{hour};
         $Syslog_LINE->{min}       = $Syslog_LINE->{rx_min}       || $Syslog_LINE->{min};
         $Syslog_LINE->{sec}       = $Syslog_LINE->{rx_sec}       || $Syslog_LINE->{sec};
         $Syslog_LINE->{year}      = $Syslog_LINE->{rx_year}      || $Syslog_LINE->{year};
         $Syslog_LINE->{wday}      = $Syslog_LINE->{rx_wday}      || $Syslog_LINE->{wday};
         $Syslog_LINE->{wday_str}  = $Syslog_LINE->{rx_wday_str}  || $Syslog_LINE->{wday_str};
         $Syslog_LINE->{date_str}  = $Syslog_LINE->{rx_date_str}  || $Syslog_LINE->{date_str};
         
         log_debug(2, "INFO: using rx_time info instead of message timestamp info\n");
      }
   }
   #
   # check filters
   #
   if ($obj->{filter}) {
      # check min date filter
      if ($obj->{filter_min_date_epoch}) {
         log_debug(3, "INFO: MIN filter: min_date_epoch [%s] [%s]\n", 
            commify($obj->{filter_min_date_epoch}), $obj->{filter_min_date},
         );
         if ($Syslog_LINE->{rx_epoch} && $obj->{rx_time}) {
            log_debug(3, "rx_epoch and rx_time : true\n");
            log_debug(3, "is %s < %s\n", commify($Syslog_LINE->{rx_epoch}), 
               commify($obj->{filter_min_date_epoch})
            );
            if ($Syslog_LINE->{rx_epoch} < $obj->{filter_min_date_epoch}) { 
               $ERROR = sprintf("rx date %s less than min filter date %s",
                  $Syslog_LINE->{rx_date_str}, $obj->{filter_min_date}
               );
               log_debug(3, "%s\n", $ERROR);
               return(wantarray ? (undef, $ERROR) : undef);
            }
         }
         elsif ($Syslog_LINE->{epoch}) {
            log_debug(3, "examine message timestamp epoch: %s\n", commify($Syslog_LINE->{epoch}));
            log_debug(3, "check %s < %s\n", 
               commify($Syslog_LINE->{epoch}), commify($obj->{filter_min_date_epoch})
            );
            if ($Syslog_LINE->{epoch} < $obj->{filter_min_date_epoch}) {
               $ERROR = sprintf("message date %s less than min filter date %s",
                  $Syslog_LINE->{date_str}, $obj->{filter_min_date}
               );
               log_debug(3, "NULL line: %s\n", $ERROR);
               return(wantarray ? (undef, $ERROR) : undef);
            }
            log_debug(3, "keep line\n");
         }
         else {
            $ERROR = sprintf("assert min date filter: no date from message");
            log_debug(3, "%s\n", $ERROR);
            return(wantarray ? (undef, $ERROR) : undef);
         }
      }
      # check max date filter
      if ($obj->{filter_max_date_epoch}) {
         log_debug(3, "INFO: MAX filter: max_date_epoch [%s]\n", 
            commify($obj->{filter_max_date_epoch}), $obj->{filter_max_date},
         );
         if ($Syslog_LINE->{rx_epoch} && $obj->{rx_time}) { 
            log_debug(3, "rx_epoch and rx_time : true\n");
            log_debug(3, "is %s < %s\n", commify($Syslog_LINE->{rx_epoch}),
               commify($obj->{filter_max_date_epoch})
            );
            if ($Syslog_LINE->{rx_epoch} > $obj->{filter_max_date_epoch}) { 
               $ERROR = sprintf("rx date %s greater than than max filter date %s",
                  $Syslog_LINE->{rx_date_str}, $obj->{filter_max_date}
               ); 
               log_debug(3, "%s\n", $ERROR);
               return(wantarray ? (undef, $ERROR) : undef); 
            }
         }
         elsif ($Syslog_LINE->{epoch}) {
            log_debug(3, "examine message timestamp epoch: %s\n", commify($Syslog_LINE->{epoch}));
            log_debug(3, "check %s < %s\n",
               commify($Syslog_LINE->{epoch}), commify($obj->{filter_max_date_epoch})
            );
            if ($Syslog_LINE->{epoch} > $obj->{filter_max_date_epoch}) {
               $ERROR = sprintf("message date %s greater than max filter date %s",
                  $Syslog_LINE->{date_str}, $obj->{filter_max_date}
               );
               log_debug(3, "NULL line: %s\n", $ERROR);
               return(wantarray ? (undef, $ERROR) : undef);
            }
            log_debug(3, "keep line\n");
         }
         else {
            $ERROR = sprintf("assert min date filter: no date from message");
            log_debug(3, "%s\n", $ERROR);
            return(wantarray ? (undef, $ERROR) : undef);
         }
      }
      # check device filter
      if ($obj->{filter_device}) {
         if ($Syslog_LINE->{device} !~ /$obj->{filter_device}/) {
            $ERROR = sprintf("device [%s] not match filter [%s]", $Syslog_LINE->{device}, $obj->{filter_device});
            return(wantarray ? (undef, $ERROR) : undef);
         }
      }
      # check tag filter
      if ($obj->{filter_tag}) {
         if ($Syslog_LINE->{tag} !~ /$obj->{filter_tag}/) { 
            $ERROR = sprintf("tag [%s] not match filter [%s]", $Syslog_LINE->{tag}, $obj->{filter_tag});
            return(wantarray ? (undef, $ERROR) : undef);
         }
      }
      # check message filter
      if ($obj->{filter_message}) {
         if ($Syslog_LINE->{message} !~ /$obj->{filter_message}/) { 
            $ERROR = sprintf("message not match filter [%s]", $obj->{filter_message});
            return(wantarray ? (undef, $ERROR) : undef);
         }
      }
   }  # end filtering

   # 
   # Dump and/or Report line
   #
   # if a 'last message line'
   if ($obj->{lastmsg} && $Syslog_LINE->{line} =~ /last message repeated (\d+) time/) {
      $_last = $1;
      $Syslog_LINE = undef;
      %{$Syslog_LINE} = %LASTMSG;
      log_debug(2, "syslog line repeated: [%s] times\n", $_last);
      foreach  (1..$_last) {
         log_debug(3, "syslog line repeat: [%s]\n", $_);
         if ($obj->{dump}) 
            {&dump_line_to_file($obj, $Syslog_LINE->{device}, $Syslog_LINE->{line});}
         if ($obj->{report}) 
            {&dump_to_datalist;}
      } 
   }
   else {
      # see if we want to dump file
      if ($obj->{dump} && $Syslog_LINE->{device}) {
         ($_ok, $ERROR) = &dump_line_to_file($obj, $Syslog_LINE->{device}, $_line);
         unless ($_ok)
            {return(wantarray ? (undef, $ERROR) : undef);}
      }

      # see if we want a report
      if ($obj->{report}) 
         {&dump_to_datalist;}
   }

   # store this line for next iteration
   %LASTMSG = %{$Syslog_LINE};

   {return(wantarray ? ($Syslog_LINE, $ERROR) : $Syslog_LINE);}

}   # end parse_syslog_line 
#
#.............................................................................
#
# Function/method to parse portion of syslog line thought to contain
# the syslog message
#
# Break syslog line into parts
#   timestamp device message
#                  message = tag content
#
# $_[0] - syslog line or rfc 3164 portion
# $_[1] - undef | 1  # set to one if called internally, used to control return call
#
# Return
#   (timestamp, host, message, $ERROR) : \%hash


sub parse_syslog_msg {

   my $_msg = shift;
   my $_ret = shift || 0;

   my ($_ok, $_err,
       $_x1, $_x2, 
   );

   #
   # Extract timestamp device message
   #
   # Mmm|mmm d|dd hh:mm:ss device message
   if ($_msg =~ /([JFMASONDjfmasond]\w\w {1,2}\d+ [0-9:]+) (\S+) (.+)/) {
      $Syslog_LINE->{timestamp} = $1;
      $Syslog_LINE->{device}    = $2;
      $Syslog_LINE->{message}   = $3;
      if ($DEBUG) {
         log_debug(1, "parse syslog message timestamp: [%s]\n", $Syslog_LINE->{timestamp});
         log_debug(1, "parse syslog message device:    [%s]\n", $Syslog_LINE->{device});
         log_debug(1, "parse syslog message:           [%s]\n", $Syslog_LINE->{message});

      }
   }
   else {
      $ERROR = "unsupport syslog message format: $_msg";
      log_debug(1, "%s\n", $ERROR);
      if ($_ret) {return(undef);}
      else       {return(wantarray ? (undef, undef, undef, $ERROR) : undef) }
   }

   # see if device has been substituted with ip/port info [a.a.a.a.p.p]
   # such as 10.1.1.1.4.0
   # convert last two octets to srcPort
   #   convert decimal octet to hex, join together, convert hex to decimal
   if ($Syslog_LINE->{device} =~ /(\d+\.\d+\.\d+\.\d+)\.(\d+)\.(\d+)/) {
      $Syslog_LINE->{device} = $1;
      $Syslog_LINE->{device_port} = hex( join('', sprintf("%02x", $2), sprintf("%02x", $3))); 
   }
   else {
      $Syslog_LINE->{device_port} = '?';
   }


   #
   # parse timestamp
   #
   if ( defined($Syslog_LINE->{timestamp}) ) {
      # Mmm  d hh:mm:ss    mmm  d hh:mm:ss
      # Mmm dd hh:mm:ss    mmm dd hh:mm:ss
      if ($Syslog_LINE->{timestamp} =~ /([JFMASOND]\w\w)\s+(\d+)\s((\d\d):(\d\d):(\d\d))/i) {
         $Syslog_LINE->{month_str} = $1;
         $Syslog_LINE->{day}       = $2;
         $Syslog_LINE->{time_str}  = $3;
         $Syslog_LINE->{hour}      = $4;
         $Syslog_LINE->{min}       = $5;
         $Syslog_LINE->{sec}       = $6;

         $Syslog_LINE->{month}     = $MON_index{$Syslog_LINE->{month_str}};
         $Syslog_LINE->{year}      = $YEAR;
         log_debug(2, 
            "syslog message timestamp values: Mmm: [%s] [%s] dd: [%s] hh: [%s] mm: [%s] ss: [%s]\n",
            $Syslog_LINE->{month_str}, $Syslog_LINE->{month},
            $Syslog_LINE->{day}, $Syslog_LINE->{hour},
            $Syslog_LINE->{min}, $Syslog_LINE->{sec}
         );

 
         # determine some time info
         #   year, epoch seconds, weekday
         #
         log_debug(2, "determine message epoch and wday\n");   
         ($Syslog_LINE->{epoch}, $Syslog_LINE->{wday}) =
            &_extra_time_values(
               $Syslog_LINE->{sec}, $Syslog_LINE->{min}, $Syslog_LINE->{hour},
               $Syslog_LINE->{day}, $Syslog_LINE->{month},
         );
         $Syslog_LINE->{wday_str} = $WDAY{$Syslog_LINE->{wday}};
         $Syslog_LINE->{date_str} = epoch_to_datestr($Syslog_LINE->{epoch});
 
         log_debug(2, "syslog message timestamp extra: yyyy: [%s] epoch: [%s] wday: [%s] [%s]\n",
               $Syslog_LINE->{year}, $Syslog_LINE->{epoch}, $Syslog_LINE->{wday},
               $Syslog_LINE->{wday_str}
         );
      }
   }
   else {
      $ERROR = "unsupported timestamp syntax: $Syslog_LINE->{timestamp}";
      log_debug(1, "%s\n", $ERROR);
      if ($_ret) {return(undef);}
      else       {return(wantarray ? (undef, undef, undef, $ERROR) : undef) }
   }

   #
   # parse message part
   #   tag content
   #   tag: content
   #   tag[pid]: content
   #
   #
   if (defined($Syslog_LINE->{message}) ) {
      $Syslog_LINE->{message} =~ s/^\s+//;
      # last message repeated # time
      if ($Syslog_LINE->{message} =~ /last message repeated \d+ time/) {
         $Syslog_LINE->{tag}      = 'lastmsg';
         $Syslog_LINE->{pid}      = '';
         $Syslog_LINE->{content}  = '';
      }

      # tag[pid]: content
      elsif ($Syslog_LINE->{message} =~ /^([\w\d]+)\[([\w\.\- ]+)\]: *(.+)/) {
         $Syslog_LINE->{tag}     = $1;
         $Syslog_LINE->{pid}     = $2;
         $Syslog_LINE->{content} = $3;
      }
      # tag: content
      elsif ($Syslog_LINE->{message} =~ /^([\w\d]+): +(.+)/) {
         $Syslog_LINE->{tag}     = $1;
         $Syslog_LINE->{content} = $2;
         $Syslog_LINE->{pid}     = '';
      }
      # tag content
      elsif ($Syslog_LINE->{message} =~ /^(\w{1,32}) (.+)/) {
         $Syslog_LINE->{tag}     = $1;
         $Syslog_LINE->{content} = $2;
         $Syslog_LINE->{pid}     = '';
      }
      else {
         $Syslog_LINE->{tag}     = 'noTag';
         $Syslog_LINE->{pid}     = '';
         $Syslog_LINE->{content} = $Syslog_LINE->{message};
      }

      if ($DEBUG) {
         log_debug(2, "syslog message:  tag: [%s] pid [%s]\n", 
            $Syslog_LINE->{tag}, $Syslog_LINE->{pid}
         );
         log_debug(2, "syslog message:  content: %s\n", $Syslog_LINE->{content});
      }


   }   # end defined($Syslog_LINE->{message})

   # return some values
   if ($_ret) {return(1);}
   else {
      return(wantarray ? ($Syslog_LINE->{timestamp},
                          $Syslog_LINE->{device},
                          $Syslog_LINE->{message},
                          undef,
                         )
                         : $Syslog_LINE
      );
   }
}   # end parse_syslog_msg 
#
#.............................................................................
#
#  function to parse preamble
#     yyyy-mm-dd hh:mm::ss facility.severity src_ip
#     mm-dd-yyyy hh:mm::ss facility.severity src_ip
#
#  Arg
#   $_[0]  preamble
#
# Return
#   (epoch, date, facility, severity, srcIP)
#
sub parse_preamble  {

   my @_tokens = ();
   my ($_t, $_epoch, $_timestamp, $_date, $_time,
       $_yr, $_mon, $_day,
       $_hr, $_min, $_sec,
       $_prio, $_fac, $_sev, $_srcIp
   );

   if ($_[0] =~ /^<(\d+)>$/) {
      $_prio = $1;
      @_tokens= decode_PRI($_prio);
      $_prio = $_tokens[3];
      $_fac  = $_tokens[4];
      $_sev  = $_tokens[5];
   }
   else {
      @_tokens = split(/\s+/, $_[0]);
      foreach $_t (@_tokens) {
         # yyyy-mm-dd
         if ($_t =~ /(\d\d\d\d)\-(\d\d)\-(\d\d)/) {
            $_yr  = $1;  $_mon = $2;   $_day = $3;
            $_date = $_t;
         }
         # mm-dd-yyyy
         if ($_t =~ /(\d\d)\-(\d\d)\-(\d\d\d\d)/) {
            $_mon = $1; $_day = $2; $_yr = $3;
            $_date = $_t;
         }
         # hh:mm::ss
         if ($_t =~ /(\d\d):(\d\d):(\d\d)/) {
            $_hr = $1;  $_min = $2;   $_sec = $3; 
            $_time = $_t;
         }
         # facility.severity
         if ($_t =~ /([a-zA-Z0-9]+)\.([a-zA-Z]+)/)
            {$_fac = $1;  $_sev = $2;  $_prio = $_t;}
         # source IP
         if ($_t =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
            {$_srcIp = $1;}
      }
      $_timestamp = sprintf("%s %s", $_date, $_time);
      $_timestamp =~ s/^\s+//;
      $_timestamp =~ s/\s+$//;

      $_epoch = timelocal($_sec, $_min, $_hr, $_day, $_mon-1, $_yr);
   }

   $Syslog_LINE->{preamble}      = $_[0];

   if ($_prio) {
      $Syslog_LINE->{rx_priority}   = $_prio;
      $Syslog_LINE->{rx_facility}   = $_fac;
      $Syslog_LINE->{rx_severity}   = $_sev;
   }

   if ($_timestamp) {
      $Syslog_LINE->{rx_timestamp}  = $_timestamp;
      $Syslog_LINE->{rx_epoch}      = $_epoch;
      $Syslog_LINE->{rx_date_str}   = epoch_to_datestr($Syslog_LINE->{rx_epoch});
      $Syslog_LINE->{rx_year}       = $_yr;
      $Syslog_LINE->{rx_month}      = $_mon-1;
      $Syslog_LINE->{rx_month_str}  = $MON{$_mon-1};
      $Syslog_LINE->{rx_day}        = $_day;
      $Syslog_LINE->{rx_wday}       = (localtime($Syslog_LINE->{rx_epoch}))[6];
      $Syslog_LINE->{rx_wday_str}   = $WDAY{$Syslog_LINE->{rx_wday}};
      $Syslog_LINE->{rx_time_str}   = $_time;
      $Syslog_LINE->{rx_hour}       = $_hr;
      $Syslog_LINE->{rx_min}        = $_min;
      $Syslog_LINE->{rx_sec}        = $_sec;
   }

   if ($_srcIp) {
      $Syslog_LINE->{rx_srcIP}      = $_srcIp;
   }

   # normalize facility and severity strings
   if (!defined($Syslog_Facility{$Syslog_LINE->{rx_facility}})) {
      $Syslog_LINE->{rx_facility} = normalize_facility($Syslog_LINE->{rx_facility});
      log_debug(3, "normailzed facility string\n");
   }
   if (!defined($Syslog_Severity{$Syslog_LINE->{rx_severity}})) {
      $Syslog_LINE->{rx_severity} = normalize_severity($Syslog_LINE->{rx_severity});
      log_debug(3, "normailzed severity string\n");
   }


   if ($DEBUG) {
      log_debug(2, "syslog line preamble: timestamp: [%s] priority: [%s] srcIP: [%s]\n",
         $Syslog_LINE->{rx_timestamp}, $Syslog_LINE->{rx_priority},
         $Syslog_LINE->{rx_srcIP}
      );
      log_debug(3, "syslog line preamble: epoch: [%s] facility: [%s] severity: [%s]\n",
         $Syslog_LINE->{rx_epoch}, $Syslog_LINE->{rx_facility}, $Syslog_LINE->{rx_severity}
      );
      log_debug(3, "syslog line preamble: datestr: [%s]\n",
         $Syslog_LINE->{rx_date_str}
      );
   }

   1;

}   # parse_preamble

#
#.............................................................................
#
#  Init the object
sub init {
   $Syslog_LINE = undef
}
#
#=======================================================================
#
#                   Syslog Send Message
#
#=======================================================================
#
#
#........................................................................
#
# Syslog Send message constructor
#
# Args
#   server     => <syslog server>
#   port       => <syslog port>  (514)
#   facility   => <facility> 
#   severity   => <severity>
#   tag        => <tag>
#   timestamp  => <timstamp>   # timestamp value to use in syslog message
#   device     => <devname>    # device name to use in syslog message
#   tag        => <string>     # tag string to use in syslog message
#   pid        => <pid>        # pid to append to tag enclosed in []
#   message    => <message>    # message to send
#   strict     => 0|1          # enforce message syntax rules
#

sub send {

   # create object
   my $proto = shift;
   my $class = ref($proto) || $proto;
   my $send  = {};
   # bless object
   bless($send, $class);

   $ERROR = '';

   my %arg = @_;
   my $a;

   # default some values
   $send->{server}    = '127.0.0.1';
   $send->{port}      = '514';
   $send->{proto}     = 'udp';
   $send->{facility}  = 'user';
   $send->{severity}  = 'debug';
   $send->{tag}       = 'NetDevSyslog';
   $send->{pid}       = 1;
   $send->{strict}    = 1;

   # check arguments
   foreach $a (keys %arg) {
      if    ($a =~ /^-?server/)    { $send->{server}    = delete($arg{$a}); }
      elsif ($a =~ /^-?port/)      { $send->{port}      = delete($arg{$a}); }
      elsif ($a =~ /^-?proto/)     { $send->{proto}     = delete($arg{$a}); }
      elsif ($a =~ /^-?facility/)  { $send->{facility}  = delete($arg{$a}); }
      elsif ($a =~ /^-?severity/)  { $send->{severity}  = delete($arg{$a}); }
      elsif ($a =~ /^-?timestamp/) { $send->{timestamp} = delete($arg{$a}); }
      elsif ($a =~ /^-?device/)    { $send->{device}    = delete($arg{$a}); }
      elsif ($a =~ /^-?tag/)       { $send->{tag}       = delete($arg{$a}); }
      elsif ($a =~ /^-?pid/)       { $send->{pid}       = delete($arg{$a}); }
      elsif ($a =~ /^-?message/)   { $send->{message}   = delete($arg{$a}); }
      elsif ($a =~ /^-?strict/)    { $send->{strict}    = delete($arg{$a}); }
      else {
         $ERROR = sprintf("unsupported argument: %s => %s", $a, $arg{$a});
         return(wantarray ? (undef, $ERROR) : undef);
      }
   }

   return(wantarray ? ($send, $ERROR) : $send);
}


#
#.............................................................................
#
# send message
#  max length = 1024
#  PRI HEADER MSG
#    PRI 3,4 or 5 char bounded by '<' '>'
#      <#>
#
sub send_msg {

   my $send = shift;
   my ($_facility, $_severity, 
       $_timestamp, $_devname, $_tag, $_pid, $_msg,
       $_pri, $_content, $tx_msg, $msg_l, $tag_l,
       $_sock,
   );

   $ERROR = '';

   my %arg = @_;
   my $a;

   # check arguments
   foreach $a (keys %arg) {
      if    ($a =~ /^-?server/)    { $send->{server}    = delete($arg{$a}); }
      elsif ($a =~ /^-?port/)      { $send->{port}      = delete($arg{$a}); }
      elsif ($a =~ /^-?facility/)  { $send->{facility}  = delete($arg{$a}); }
      elsif ($a =~ /^-?severity/)  { $send->{severity}  = delete($arg{$a}); }
      elsif ($a =~ /^-?timestamp/) { $send->{timestamp} = delete($arg{$a}); }
      elsif ($a =~ /^-?device/)    { $send->{device}    = delete($arg{$a}); }
      elsif ($a =~ /^-?tag/)       { $send->{tag}       = delete($arg{$a}); }
      elsif ($a =~ /^-?pid/)       { $send->{pid}       = delete($arg{$a}); }
      elsif ($a =~ /^-?message/)   { $send->{message}   = delete($arg{$a}); }
      elsif ($a =~ /^-?strict/)    { $send->{strict}    = delete($arg{$a}); }
      else {
         $ERROR = sprintf("unsupported argument: %s => %s", $a, $arg{$a});
         return(wantarray ? (undef, $ERROR) : undef);
      }
   }

   # error check facility and severity value
   if (!defined($Syslog_Facility{$send->{facility}})) {
      $ERROR = "unsupported argument: facility => $send->{facility}";
      return(wantarray ? (undef, $ERROR) : undef);
   }
   if (!defined($Syslog_Severity{$send->{severity}})) {
      $ERROR = "unsupported argument: severity => $send->{severity}";
      return(wantarray ? (undef, $ERROR) : undef);
   }

   $_tag = undef;
   $_msg = '';

   $_facility = $Syslog_Facility{$send->{facility}};
   $_severity = $Syslog_Severity{$send->{severity}};
   # PRI = (facility x 8) + severity
   $_pri = ($_facility * 8) + $_severity;

 
   # timestamp
   if ($send->{timestamp}) {
      if (!validate_timestamp_syntax($send->{timestamp})) {
         $ERROR = "invalid timestamp: $send->{timestamp}";
         return(wantarray ? (undef, $ERROR) : undef);
      } 
      $_timestamp = $send->{timestamp};
   }
   else {
      $_timestamp = epoch_to_timestamp();
   }

   # device name
   if ($send->{device}) {$_devname = $send->{device};}
   else                 {$_devname = hostname() || 'syslog_dev';}  
   #
   # tag
   # 
   if ($send->{tag}) {
       # tag[pid]:
      if ($send->{tag} && $send->{pid}) 
         {$_tag = sprintf("%s[%s]:", $send->{tag}, $send->{pid});}
      # tag:
      else 
         {$_tag = sprintf("%s:", $send->{tag});}
   }
   #
   # message
   # 
   if ($send->{message}) 
      {$_msg = $send->{message};}
   else {
      $_msg = sprintf("SYSLOG TEST Message:  facility: %s [%s] severity: %s [%s]", 
         $send->{facility}, $_facility, 
         $send->{severity}, $_severity
      );
   }
   #
   # Content
   #
   if ($_tag) 
      {$_content = sprintf("%s %s", $_tag, $_msg);}
   else 
      {$_content = sprintf("%s", $_msg);}

   #
   #  MESSAGE to transmit
   #
   $tx_msg = sprintf("<%s>%s %s %s", $_pri, $_timestamp, $_devname, $_content);
   $msg_l  = length($tx_msg);

   # check allowed lengths
   $msg_l  = length($tx_msg);
   if ($_tag =~ /(.+)\[/)
      {$tag_l = length($1);}
   else 
      {$tag_l = length($_tag);}

   if ($send->{strict}) {
      # syslog message length can not exceed 1024
      if ($msg_l > 1024) {
         $ERROR = "syslog message length $msg_l greater than 1024";
         return(wantarray ? (undef, $ERROR) : undef);
      }
      # syslog tag length can not exceed 32
      if ($tag_l > 32) {
         $ERROR = "syslog message tag length $tag_l greater than 32";
         return(wantarray ? (undef, $ERROR) : undef);
      }
   }
  
   if (0){
      printf("server:      %s  port %s proto %s\n", 
         $send->{server}, $send->{port}, $send->{proto}
      );
      printf("facility:    %s [%s]  severity: %s [%s]  pri: [%s]\n",
         $send->{facility}, $_facility,
         $send->{severity}, $_severity,
         $_pri
      );
      printf("timestamp:   %s  [%s]\n", $send->{timestamp} || 'localtime', $_timestamp);
      printf("device:      %s  [%s]\n", $send->{device} || 'none', $_devname);
      printf("content:     tag: %s  pid: %s  [%s]\n", $send->{tag}, $send->{pid} || '-', 
         $_tag
      );
      printf("             message: %s\n", $_msg);
      printf("             %s\n", $_content);
      printf("             lengths: tag: %s   message: %s\n", $tag_l, $msg_l);
      printf("   %s\n", $tx_msg);
   }
   
   # send the message
   $_sock = IO::Socket::INET->new(
      PeerAddr  => $send->{server},
      PeerPort  => $send->{port},
      Proto     => $send->{proto}
   ); 
   unless ($_sock) {
      $ERROR = sprintf("could not open socket to %s:%s  [%s]", 
         $send->{server}, $send->{port}, $!
      );
      return( wantarray ? (undef, $ERROR) : undef) ;
   }
   print $_sock $tx_msg; 

   $_sock->close();
   return(wantarray ? (1, $ERROR) : 1);

}   # end send_msg

#
#=======================================================================
#
#                   Syslog Receive Message
#
#=======================================================================
#
#
#........................................................................
#
# Syslog Receive message constructor
#
#  port       => <port>        port to listen on (514)
#  proto      => <protocol>    protocol (udp)
#  maxlength  => <max length>  max length of packet (1024)
#  verbose    => 0|1|2|3       verbose level  (0)
#                0 - pure message
#                1 - bsd format
#                2 - bsd_plus format
#
sub listen {

   # create object
   my $proto = shift;
   my $class = ref($proto) || $proto;
   my $listen  = {};
   # bless object
   bless($listen, $class);

   $ERROR = '';

   # on unix, you need to be root
   if ($^O !~ /win/i) {
      if ($> != 0) {
         $ERROR = "must have root uid: not $>";
         return(wantarray ? (undef, $ERROR) : undef);
      }
   }
   # define CTRL-C
   $SIG{INT} = \&interupt_listen;

   my %arg = @_;
   my ($a, $err, 
       $sock, $port, $ipaddr, $ipaddr_packed, $rhost, 
       $msg, $msg_count, 
       $obj, $parse,
   );


   # set defaults
   $listen->{port}       = 514;
   $listen->{proto}      = 'udp';
   $listen->{maxlength}  = '1024';
   $listen->{verbose}    = 0;
   $listen->{packets}    = -1;

   $listen->{report}     = 0;

   foreach $a (keys %arg) {
      if    ($a =~ /^-?port$/)       { $listen->{port}       = delete($arg{$a}); }
      elsif ($a =~ /^-?proto$/)      { $listen->{proto}      = delete($arg{$a}); }
      elsif ($a =~ /^-?maxlength$/)  { $listen->{maxlength}  = delete($arg{$a}); }
      elsif ($a =~ /^-?packets$/)    { $listen->{packets}    = delete($arg{$a}); }
      elsif ($a =~ /^-?verbose$/)    { $listen->{verbose}    = delete($arg{$a}); }
      # parser options
      elsif ($a =~ /^-?dump$/i)        {$listen->{dump}       = delete($arg{$a}); }
      elsif ($a =~ /^-?append$/i)      {$listen->{append}     = delete($arg{$a}); }
      elsif ($a =~ /^-?ext$/i)         {$listen->{ext}        = delete($arg{$a}); }
      elsif ($a =~ /^-?report$/i)      {$listen->{report}     = delete($arg{$a}); }
      elsif ($a =~ /^-?interval$/i)    {$listen->{interval}   = delete($arg{$a}); }
      elsif ($a =~ /^-?rx_time$/i)     {$listen->{rx_time}    = delete($arg{$a}); }
      elsif ($a =~ /^-?lastmsg$/i)     {$listen->{lastmsg}    = delete($arg{$a}); }
      elsif ($a =~ /^-?debug$/i)       {$listen->{debug}      = delete($arg{$a}); }
      elsif ($a =~ /^-?msg_plus$/i)    {$listen->{msg_plus}   = delete($arg{$a}); }
      elsif ($a =~ /^-?min_date$/i)    {$listen->{filter_min_date}   = delete($arg{$a}); }
      elsif ($a =~ /^-?max_date$/i)    {$listen->{filter_max_date}   = delete($arg{$a}); }
      elsif ($a =~ /^-?device$/i)      {$listen->{filter_device}     = delete($arg{$a}); }
      elsif ($a =~ /^-?tag$/i)         {$listen->{filter_tag}        = delete($arg{$a}); }
      elsif ($a =~ /^-?message$/i)     {$listen->{filter_message}    = delete($arg{$a}); }

      else {
         $ERROR = sprintf("unsupported argument: %s => %s", $a, $arg{$a});
         return(wantarray ? (undef, $ERROR) : undef);
      } 
   }

   if ($listen->{report}) {
      ($obj, $err) = Net::Dev::Tools::Syslog->parse(
         -report  => $listen->{report},
         exists($listen->{dump})     ? (-dump   => $listen->{dump})  : (),
         exists($listen->{append})   ? (-append   => $listen->{append})  : (),
         exists($listen->{ext})      ? (-ext   => $listen->{ext})  : (),
         exists($listen->{report})   ? (-report   => $listen->{report})  : (),
         exists($listen->{interval}) ? (-interval   => $listen->{interval})  : (),
         exists($listen->{rx_time})  ? (-rx_time   => $listen->{rx_time})  : (),
         exists($listen->{lastmsg})  ? (-lastmsg   => $listen->{lastmsg})  : (),
         exists($listen->{debug})    ? (-debug   => $listen->{debug})  : (),
         exists($listen->{msg_plus}) ? (-msg_plus   => $listen->{msg_plus})  : (),
         exists($listen->{min_date}) ? (-min_date   => $listen->{min_date})  : (),
         exists($listen->{max_date}) ? (-max_date   => $listen->{max_date})  : (),
         exists($listen->{device})   ? (-device   => $listen->{device})  : (),
         exists($listen->{tag})      ? (-tag   => $listen->{tag})  : (),
         exists($listen->{message})  ? (-message   => $listen->{message})  : (),
      );
      unless($obj) {
         $ERROR = "listener failed to open parser: $err";
         return(wantarray ? (undef, $ERROR) : undef);
      }
   }

   # open socket
   $sock = IO::Socket::INET->new(
      LocalPort =>  $listen->{port},
      Proto     =>  $listen->{proto},
   );
 
   unless ($sock) {
      $ERROR = sprintf("socket failed port: %s %s : %s", 
         $listen->{port}, $listen->{proto}, $@,
      );
      return(wantarray ? (undef, $ERROR) : undef); 
   }

   # listen on socket
   $msg_count = 0;
   while ($sock->recv($msg, $listen->{maxlength})) {
      printf("%s\n", $msg);
      $msg_count++;
      # print out  little more if we are verbose
      if ($listen->{verbose}) {
         ($port, $ipaddr_packed) = sockaddr_in($sock->peername);
         $ipaddr = inet_ntoa($ipaddr_packed);
         $rhost = gethostbyaddr($ipaddr_packed, AF_INET);
         printf("    Packet:     %s  from %s:%s [%s]\n",
            $msg_count, $ipaddr, $port, $rhost
         );
      }
      # parse the line if we want a report 
      if ($listen->{report}) { 
         $parse = $obj->parse_syslog_line($msg);
         if ($listen->{verbose} > 1) {
            printf("    Priority:   %s  Facility [%s]   Severity [%s]\n",
               $parse->{rx_priority}, $parse->{rx_facility}, $parse->{rx_severity}
            );
            printf("    Timestamp:  %s\n", $parse->{timestamp});
            printf("    Device:     %s\n", $parse->{device});
            printf("    Tag:        %s %s\n", $parse->{tag}, $parse->{pid});
            printf("    Content:    %s\n", $parse->{content}); 
         }
      }
      # check if we are counting packets
      if ($listen->{packets} > 0) {last if  $msg_count == $listen->{packets};}  
   }
   $sock->close;

   # close files if we reported and dumped
   if ($listen->{report} && $listen->{dump}) {$obj->close_dumps;}


   # function to handle CTRL-C
   sub interupt_listen {
       printf("CTRL-C detected: closing socket\n");
       $sock->shutdown(0);
   }

   if ($listen->{report}) {
      printf("Returning object reference\n");
      return(wantarray ? ($obj, $ERROR) : $obj);
   }
   else {
      return(wantarray ? ($msg_count, "$msg_count messages") : $msg_count);
   }
}   # end sub listen



#
#=============================================================================
#
#                   handle the files
#
#=============================================================================
#
# function to dump line to file
#
# Arg 
#   $_[0]  class
#   $_[1]  devicename
#   $_[2]  line
#
# Return 
#   1 or undef
#
sub dump_line_to_file {

   my $_h = $_[1];
   $_h =~ s/ +//g;
   my $_dstfile = sprintf("%s%s.%s",  $_[0]->{repository}, $_[1], $_[0]->{ext});

   $ERROR = '';

   log_debug(3, "syslog line dump to file: [%s]\n", $_dstfile);
   # see if we have a file handle   
   if (!defined($FH{$_h})) {
      # open for overwrite or appending
      if ($_[0]->{append} == 1) {
         open($FH{$_h}, ">>$_dstfile") or $ERROR = "open append failed: $_h: $!";
      }
      else {
         open($FH{$_h}, ">$_dstfile") or $ERROR = "open overwright failed: $_h: $!";
      }
      select $FH{$_h}; $| = 1;
      select STDOUT;   $| = 1;
   }

   # exit out if we errored
   if ($ERROR) {
      log_debug(3, "%s\n", $ERROR);
      return(wantarray ? (undef, $ERROR) : $ERROR);
   }

   my $fh = $FH{$_h};
   printf $fh ("%s\n", $_[2]);

   return(wantarray ? (1, $ERROR) : 1);

}
#
#.............................................................................
#
# function to close all files
#
#
sub close_dumps {
   my $_f;
   # close any filehandle opened for parse
   foreach $_f (keys %FH) { close($FH{$_f});}
   1; 
}

##############################################################################
#
#                      Report Functions
#
#
#.............................................................................
#
# function to populate datalist
#
# operate on global values
#                           
#

sub dump_to_datalist {

   my $_rxt  = $Syslog_LINE->{rx_timestamp} || undef;
   my $_rxe  = $Syslog_LINE->{rx_epoch}     || undef;
   my $_prio = $Syslog_LINE->{rx_priority}  || 'noFacility.noSeverity';
   my $_fac  = $Syslog_LINE->{rx_facility}  || 'noFacility';
   my $_sev  = $Syslog_LINE->{rx_severity}  || 'noSeverity';

   push(@DATA, {
                 'timestamp'    => $Syslog_LINE->{timestamp},
                 'epoch'        => $Syslog_LINE->{epoch},
                 'device'       => $Syslog_LINE->{device},
                 'tag'          => $Syslog_LINE->{tag},
                 'rx_time'      => $_rxt,
                 'rx_epoch'     => $_rxe,
                 'rx_priority'  => $_prio,
                 'rx_facility'  => $_fac,
                 'rx_severity'  => $_sev,
                 'rx_srcIP'     => $Syslog_LINE->{srcIP},
               }
    );

    1;
}

#
#.............................................................................
#
# function to derive stats
#
# Loop thru @DATA and create %STATS 
#
# Arg
#  $_[0] = class
#  min   => min date
#  max   => max date
#
#
#    @DEVICES    = list of each device found
#    @TAGS       = list of each tag found
#    @FACILITYS  = list of each facility found
#    @SEVERITYS  = list of each of each severity found
# 
#    %STATS{syslog}{messages}
#                  {tag}{<tag>}{messages}
#                  {facility}{<facility>}{messages}
#                  {severity}{<severity>}{messages}
#                  {min_epoch}
#                  {min_date_str}
#                  {max_epoch}
#                  {max_date_str}
#
#
#          {device}{<dev>}{messages}
#                         {tag}{<tag>}{messages}
#                         {facility}{<facility>}{messages}
#                         {severity}{<severity>}{messages}
#                         {min_epoch}
#                         {min_date_str}
#                         {max_epoch}
#                         {max_date_str} 
#
#
sub syslog_stats {

   %STATS = ();
   my $class = shift;
   my %arg = @_;
   my ($get_min, $get_max,
       $min_epoch, $max_epoch, 
       $data, $dev,
   );

   # see if we need to get min/max date
   # and set min/max date
   if   (defined($arg{min})) {$get_min = 0; $min_epoch = date_filter_to_epoch($arg{min});}
   else                      {$get_min = 1; $min_epoch = 2**32;}

   if   (defined($arg{max})) {$get_max = 0; $max_epoch = date_filter_to_epoch($arg{max});}
   else                      {$get_max = 1; $max_epoch = 0;}

   foreach $data (@DATA) {
      # we need to check that $data->{} has values,
      # if its empty, it can throw us off
      # such as blank line yields $data->{epoch} = ''
      #   the min value goes to this stas can be off since have no min_epoch value
      if (!defined($data->{epoch}) || !defined($data->{device}) ) {next;}

      # check filters
      if (defined($arg{min})) {next if $data->{epoch} < $min_epoch;}
      if (defined($arg{max})) {next if $data->{epoch} > $max_epoch;}

      # find min max date
      if ($get_min) {
         if ($data->{epoch} < $min_epoch) { $min_epoch = $data->{epoch}; }
      }
      if ($get_max) {
         if ($data->{epoch} > $max_epoch) { $max_epoch = $data->{epoch}; }
      }
      #
      # populate arrays
      #
      if ( !defined($STATS{device}{$data->{device}}) )
         {push(@DEVICES,   $data->{device});}
      if ( !defined($STATS{syslog}{tag}{$data->{tag}}) )
         {push(@TAGS,      $data->{tag});}
      if ( !defined($STATS{syslog}{facility}{$data->{rx_facility}}) )
         {push(@FACILITYS, $data->{rx_facility});}
      if ( !defined($STATS{syslog}{severity}{$data->{rx_severity}}) )
         {push(@SEVERITYS, $data->{rx_severity});}


      # per syslog
      $STATS{syslog}{messages}++;
      $STATS{syslog}{tag}{$data->{tag}}{messages}++;
      $STATS{syslog}{facility}{$data->{rx_facility}}{messages}++;
      $STATS{syslog}{severity}{$data->{rx_severity}}{messages}++;

      # per device 
      $STATS{device}{$data->{device}}{messages}++;
      $STATS{device}{$data->{device}}{tag}{$data->{tag}}{messages}++;
      $STATS{device}{$data->{device}}{facility}{$data->{rx_facility}}{messages}++;
      $STATS{device}{$data->{device}}{severity}{$data->{rx_severity}}{messages}++;

      # check for min/max existence 
      if (!defined($STATS{device}{$data->{device}}{min_epoch}))
         {$STATS{device}{$data->{device}}{min_epoch} = 2**32;}
      if (!defined($STATS{device}{$data->{device}}{max_epoch}))
         {$STATS{device}{$data->{device}}{max_epoch} = 0;}
      # find min/max per device
      if($data->{epoch} < $STATS{device}{$data->{device}}{min_epoch})
         {$STATS{device}{$data->{device}}{min_epoch} = $data->{epoch};}
      if($data->{epoch} > $STATS{device}{$data->{device}}{max_epoch})
         {$STATS{device}{$data->{device}}{max_epoch} = $data->{epoch};}

   }  # foreach $data

   # set min/max date for whole syslog 
   $STATS{syslog}{min_epoch} = $min_epoch;
   $STATS{syslog}{max_epoch} = $max_epoch;


   $STATS{syslog}{min_date_str} = epoch_to_datestr($STATS{syslog}{min_epoch});
   $STATS{syslog}{max_date_str} = epoch_to_datestr($STATS{syslog}{max_epoch});
   # set min/max date_str for each device
   foreach $dev (keys %{$STATS{device}}) {
      $STATS{device}{$dev}{min_date_str} = epoch_to_datestr($STATS{device}{$dev}{min_epoch});
      $STATS{device}{$dev}{max_date_str} = epoch_to_datestr($STATS{device}{$dev}{max_epoch});
   }

   return(\%STATS);

}   # end sub syslog_stats




#############################################################################
#
#                   Timestamp Functions
#
#.............................................................................
#
# function to convert epoch to (month, day, hour, epoch_start_of_day)
#    epoch_time_of_day for this (month, day, hour)
#
# Arg 
#  epoch seconds
# Return
#  (month, day, hr, min, epoch_start_of_day, epoch_end_of_day);
#
sub _epoch_to_mdhm  {

   #                     0    1    2     3     4    5     6     7     8
   # localtime(epoch) = ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)
   my @_val = localtime($_[0]);

   #                                   sec min hr  mday      mon       yr
   my $_epoch_start_of_day = timelocal(0,  0,  0,  $_val[3], $_val[4], $YEAR);
   my $_epoch_end_of_day   = timelocal(59, 59, 23, $_val[3], $_val[4], $YEAR);  

   return($MON{$_val[4]}, $_val[3], $_val[2], $_val[1], $_epoch_start_of_day, $_epoch_end_of_day);
}
# 
#.............................................................................
#
# function to convert epoch seconds to timestamp
# if no epoch seconds are given, current epoch seconds are used
#
# Arg
#   $_[0] = epoch seconds
# Return
#   Mmm  d hh:mm:ss
#   Mmm dd hh:mm:ss
#
sub epoch_to_timestamp {

   my $epoch = shift || time;
   my @t     = localtime($epoch);

   sprintf("%3s %2s %02s:%02s:%02s", 
      $MON{$t[4]+1}, $t[3], $t[2], $t[1], $t[0]
   ); 

}
#.............................................................................
#
# function to convert epoch seconds to common date string (datestr)
#
# Arg
#  $_[0] = epoch
#
# Return
#   date string
#
#
sub epoch_to_datestr {

   my $_epoch   = shift || time;
   my $_datestr = '';

   my @_tokens = localtime($_epoch);

   my $_month = $MON{$_tokens[4]+1}; 

   $_datestr = sprintf("%s/%s/%s %02s:%02s:%02s",
      $_month, $_tokens[3], $_tokens[5]+1900,
      $_tokens[2], $_tokens[1], $_tokens[0],
   );

   log_debug(3, "epoch_to_datestr %s => [%s]    [%s] [%s] [%s]\n",
      $_epoch, $_datestr, 
      $_month, $_tokens[3], $_tokens[5]+1900,
   );

   $_datestr;
}


#
#.............................................................................
#
# function to convert date give as a filter to an epoch
#
# Arg
#  $_[0]  = mm/dd/yyyy hh:mm:ss
sub date_filter_to_epoch {

   my $_str = shift;
   my ($_mon, $_day, $_yr, $_hr, $_min, $_sec, $_epoch);


   # if Mmm/dd/yyyy   convert month alpha string to decimal
   if ($_str =~ /([JFMASONDjfmasond]\w\w)\/\d{1,2}\//) {
      $_str =~ s/$1/$MON_index{$1}/;
   }


   # mm/dd/yyyy hh:mm:ss
   if ($_str =~ /^(\d{1,2})\/(\d{1,2})\/(\d{1,4}) (\d{1,2}):(\d{1,2}):(\d{1,2})$/) {
      $_mon = $1;   $_day = $2;  $_yr  = $3;
      $_hr  = $4;   $_min = $5;  $_sec = $6;
   }
   # mm/dd/yyyy hh:mm
   elsif ($_str =~ /^(\d{1,2})\/(\d{1,2})\/(\d{1,4}) (\d{1,2}):(\d{1,2})$/) {
      $_mon = $1;   $_day = $2;  $_yr  = $3;
      $_hr  = $4;   $_min = $5;   $_sec = 0;
   }
   # mm/dd/yyyy hh
   elsif ($_str =~ /^(\d{1,2})\/(\d{1,2})\/(\d{1,4}) (\d{1,2})$/) {
      $_mon = $1;   $_day = $2;  $_yr  = $3;
      $_hr  = $4;   $_min = 0;   $_sec = 0;
   }

   # mm/dd/yyyy
   elsif ($_str =~ /^(\d{1,2})\/(\d{1,2})\/(\d{1,4})$/) {
      $_mon = $1;   $_day = $2;  $_yr  = $3;
      $_hr  = 23;   $_min = 59;  $_sec = 59;
   }
   # assert
   else {
      $ERROR = "unsupported date filter: $_str";
      return(undef);
   }

   $_epoch = timelocal($_sec, $_min, $_hr, $_day, $_mon-1, $_yr);

   return($_epoch);

}   # end date_filter_to_epoch


#
#.............................................................................
#
# function to validate syslog timestamp
#
#   Mmm  d hh:mm:ss
#   Mmm dd hh:mm:ss
#
# Arg
#  $_[0] = timestamp
#
# Return 
#   0 - not valid
#   1 - valid
sub validate_timestamp_syntax {
   if ($_[0] =~ /[JFMASONDjfmasond]\w\w  \d \d\d:\d\d:\d\d/) 
      {return(1);}
   elsif ($_[0] =~ /[JFMASONDjfmasond]\w\w \d\d \d\d:\d\d:\d\d/) 
      {return(1);}
   else
      {return(0);}
}


# 
#.............................................................................
#
# function to timeslots based on min/max epoch 
# make global array
#   @TIMESLOTS = ([index, low, high], ...)
#          index = Mmm-dd-hh:mm

#
# Arg
#   $_[0] = min epoch
#   $_[1] = max epoch
#   $_[2] = interval
#
#
sub make_timeslots {

   my $_min_epoch = shift;
   my $_max_epoch = shift;
   my $_int       = shift || 3600;

   my ($_time, $_idx);

   # check that we have min/max
   if (!$_min_epoch || !$_max_epoch) {
      $ERROR = "min epoch [$_min_epoch] or max epoch [$_min_epoch] not defined";
      return( wantarray ? (undef, $ERROR) : undef);
   }
   # check min < max
   if ($_min_epoch > $_max_epoch) {
      $ERROR = "min epoch [$_min_epoch] > max epoch [$_min_epoch]";
      return( wantarray ? (undef, $ERROR) : undef);
   }
   # interval can be no less than 60
   if ($_int < 60) {
      $_int = 60;
   }

   for ($_time = $_min_epoch; $_time <= $_max_epoch; $_time = $_time + $_int) {
      log_debug(3, "report time: %s\n", $_time);
      $_idx = epoch_to_datestr($_time);
      push(@TIMESLOTS, [$_idx, $_time, $_time + ($_int - 1)]);
      log_debug(3, "report timeslot: %s  %s => %s\n",
         $_idx, $_time, $_time + ($_int - 1)
      );
   }
   return( wantarray ? (1, undef) : 1);
}



# 
#.............................................................................
#
# function to return index that tx_time belongs to, info stored @TIMESLOTS
# read in epoch seconds, find element in @INFO whose whose rang include
# this arg value
# return index
#  @TIMESLOTS = ([index, low_epoch, high_epoch], ...)
#  
# Arg
#   $_[0] = epoch of timestamp
#
# Return
#  timeslot index for stats
#
sub epoch_timeslot_index {

   my $_i;
   foreach $_i (@TIMESLOTS) {
      if($_[0] >= $_i->[1] && $_[0] <= $_i->[2]) {
         return($_i->[0]);
      }
   }
   undef;

}

#
#.............................................................................
#
# function to get extra time info:  year and weekday
#
# Arg
#   sec, min, hour, day, month
# Return
#   wantarray ? ($_epoch, $_wday) : $_epoch
#
sub _extra_time_values {

   $_[4]--;   # 0 base the month

   my $_epoch  = timelocal(@_, $YEAR);
   my $_wday   = (localtime($_epoch))[6];
   if ($DEBUG) {
      log_debug(3, "determine epoch and wday: s:%s m:%s h:%s d:%s mon: %s\n",
         @_
      );
      log_debug(3, "epoch: %s  wday: [%s]\n", $_epoch, $_wday);
   }
   
   return(wantarray ? ($_epoch, $_wday) : $_epoch);

}
#
#=============================================================================
#
# function to decode PRI to facility and severity
#
# Arg
#  $_[0]  = PRI  
#
# Return  (lower case are decimal, upper case are strings)
#   pri, facility, severity, PRI, Facility, Severity

sub decode_PRI {

   my ($_p, $_f, $_s, $_F, $_S, $_P);

   $_p = $_[0];
   # strip out '<>' that bound PRI
   if ($_[0] =~ /[<|>]/) {
      $_p =~ s/<//;
      $_p =~ s/>//;
   }

   # check that decimal number is between 0->191
   if ($_p >= 0 && $_p <= 191) {
      $_f = int($_p/8);
      $_s = $_p - ($_f*8);

      $_F = $Facility_Index{$_f} || "?$_f?";
      $_S = $Severity_Index{$_s} || "?$_s?";
      $_P = sprintf("%s.%s", $_F, $_S);

      return(wantarray ? ($_p, $_f, $_s, $_P, $_F, $_S) : $_P );
   }
   # otherwise error out
   else {
      return(wantarray ? (-1, -1, -1, 'P?', 'F?', 'S?') : undef );
   }

}


#
#.............................................................................
#
#  function to normalize facility string
#
sub normalize_facility {

   my $_str = '';

   if    ($_[0] =~ /kern/i)     {$_str = 'kern'}
   elsif ($_[0] =~ /user/i)     {$_str = 'user'}
   elsif ($_[0] =~ /mail/i)     {$_str = 'mail'}
   elsif ($_[0] =~ /daemon/i)   {$_str = 'daemon'}
   elsif ($_[0] =~ /auth/i)     {$_str = 'auth'}
   elsif ($_[0] =~ /syslog/i)   {$_str = 'syslog'}
   elsif ($_[0] =~ /lpr/i)      {$_str = 'lpr'}
   elsif ($_[0] =~ /news/i)     {$_str = 'news'}
   elsif ($_[0] =~ /uucp/i)     {$_str = 'uucp'}
   elsif ($_[0] =~ /cron/i)     {$_str = 'cron'}
   elsif ($_[0] =~ /auth/i)     {$_str = 'authpriv'}
   elsif ($_[0] =~ /ftp/i)      {$_str = 'ftp'}
   elsif ($_[0] =~ /ntp/i)      {$_str = 'ntp'}
   elsif ($_[0] =~ /audit/i)    {$_str = 'audit'}
   elsif ($_[0] =~ /alert/i)    {$_str = 'alert'}
   elsif ($_[0] =~ /at/i)       {$_str = 'at'}
   elsif ($_[0] =~ /local0$/i)  {$_str = 'local0'}
   elsif ($_[0] =~ /local1$/i)  {$_str = 'local1'}
   elsif ($_[0] =~ /local2$/i)  {$_str = 'local2'}
   elsif ($_[0] =~ /local3$/i)  {$_str = 'local3'}
   elsif ($_[0] =~ /local4$/i)  {$_str = 'local4'}
   elsif ($_[0] =~ /local5$/i)  {$_str = 'local5'}
   elsif ($_[0] =~ /local6$/i)  {$_str = 'local6'}
   elsif ($_[0] =~ /local7$/i)  {$_str = 'local7'}
   else                         {$_str = $_[0];}

   return($_str);
}
#
#.............................................................................
#
#  function to normalize severity string
#
sub normalize_severity {

   my $_str = '';

   if    ($_[0] =~ /emerg/i)   {$_str = 'emerg'}
   elsif ($_[0] =~ /alert/i)   {$_str = 'alert'}
   elsif ($_[0] =~ /crit/i)    {$_str = 'crit'}
   elsif ($_[0] =~ /err/i)     {$_str = 'err'}
   elsif ($_[0] =~ /warn/i)    {$_str = 'warn'}
   elsif ($_[0] =~ /notice/i)  {$_str = 'notice'}
   elsif ($_[0] =~ /info/i)    {$_str = 'info'}
   elsif ($_[0] =~ /debug/i)   {$_str = 'debug'}
   else                        {$_str = $_[0];}

   return($_str);

}

#
#.............................................................................
#
#
sub log_debug {

   my $_level  = shift;
   my $_format = shift;


   if ($_level <= $DEBUG) {
      printf("debug:  $_format", @_);
   }

   1;
}
#
#.............................................................................
# 
# function to set $YEAR
#
# call
#   $obj->set_year(1988);
#
# Arg
#    $_[0] = class
#    $_[1] = year to set to, else set to current year
#
# Return
#    $YEAR
#
#
sub set_year {
   my $class = shift;
   $YEAR     = shift || ((localtime)[5]) + 1900;
   $YEAR;
}

#
#.............................................................................
# 
# functions to return references to data structures
#
sub data_aref      { return(\@DATA); }
sub stats_href     { return(\%STATS); }
sub device_aref    { return(\@DEVICES); }
sub facility_aref  { return(\@FACILITY); }
sub severity_aref  { return(\@SEVERITY); }
sub tag_aref       { return(\@TAGS); }
sub timeslot_aref  { return(\@TIMESLOTS); }

sub error          {return($ERROR);}



#
#.............................................................................
#
sub commify {
    my $text = reverse $_[0];
    $text =~ s/(\d\d\d)(?=\d)(?!\d*\.)/$1,/g;
    return scalar reverse $text;
}



1;  # end package Net::Dev::Tools::Syslog


#=============================================================================
#
#                                 POD
#
#=============================================================================

=pod

=head1 NAME

Net::Dev::Tools::Syslog - Send, Listen Syslog messages, Parse syslog files.

=head1 VERSION

Net::Dev::Tools::Syslog 0.8.0

=head1 SYNOPSIS

    use Net::Dev::Tools::Syslog;

    #
    # Syslog Parser
    #
    ($syslog, $error) = Net::Dev::Tools::Syslog->parse(
        -dump        =>  <directory>,
        -append      =>  <0|1>,
        -ext         =>  <extension>,
        -report      =>  <0|1>,
        -interval    =>  <seconds>,
        -debug       =>  <0|1|2|3>,
        -rx_time     =>  <0|1>,
        -lastmsg     =>  <0|1>,
        -min_date    =>  <mm/dd/yyyy [hh:mm]>,
        -max_date    =>  <mm/dd/yyyy [hh:mm]>,
        -device      =>  <pattern>,
        -tag         =>  <pattern>,
        -message     =>  <pattern>,
    );

    $parse = $syslog->parse_syslog_line(<line>);

    #
    # Syslog Send
    #
    ($send, $error) = Net::Dev::Tools::Syslog->send(
         -server    => <address>,
         -port      => <IP port>,
         -proto     => <udp|tcp>,
         -facility  => <facility>,
         -severity  => <severity>,
         -timestamp => <timestamp>,
         -device    => <device name>,
         -tag       => <tag>,
         -pid       => <pid>,
         -message   => <message>,
         -strict    => <0|1>,
    );

    $send->send_msg(
         -server    => <address>,
         -port      => <IP port>,
         -proto     => <udp|tcp>,
         -facility  => <facility>,
         -severity  => <severity>,
         -timestamp => <timestamp>,
         -device    => <device name>,
         -tag       => <tag>,
         -pid       => <pid>,
         -message   => <message>,
         -strict    => <0|1>,
    );

    #
    # Syslog Listen
    #
    ($listen, $error) = Net::Dev::Tools::Syslog->listen(
        -port       => <IP port>, 
        -proto      => <udp|tcp>,
        -maxlength  => <integer>
        -verbose    => <0|1|2|3>,
    );


=head1 DESCRIPTION

Module provides methods to parse syslog files, send syslog messages to
syslog server, listen for syslog message on localhost.

=over 4

=item Parser

    parse method creates a class that will parse information from
    a syslog file entry (line) and return the information to the user.
    The object is first created with properties that define how 
    a syslog line is to be worked on. The parse_syslog_line function
    (method) is then used to parse the syslog line and return a 
    reference to a hash.

=item Send

    send method will send a syslog message to a syslog sever. The user
    can provide as much or as little information desired. The class
    will then create a syslog message from the information given
    or from default values and send the message to the desired server.

=item Listen

    listen will open the desired port on the local host to listen
    for sylog messages. Message received on the port are assumed to 
    be syslog messages and are printed to STDOUT. 

=back

See documentation for individual function/methods for more detail
on usage and operation.

=head1 Syslog Message Syntax

RFC 3164 describes the syntax for syslog message. This modules
is intended to adhere to this description.

As described in the RFC, 'device' is a machine that can generate a message.
A 'server' is a machine that receives the message and does not relay it to 
any other machine. Syslog uses UDP for its transport and port 514 (server side)
has been assigned to syslog. It is suggested that the device source port also
be 514, since this is no mandatory, this module does not enforce it. 

Section 4.1 of RFC 3164 defines syslog message parts, familiarity with these
descriptions will give the user a better understanding of the functions
and arguments of this module. Maximum length of a syslog message must be 1024
bytes. There is no minimum length for a syslog message. A message of 0 bytes
should not be transmitted. 

=head2 PRI

4.1.1 PRI Part of RFC 3164 describes PRI. The PRI represents the syslog 
Priority value which represents the Facility and Severity as a decimal 
number bounded by angle brackets '<''>'. The PRI will have 3,4 or 5 characters. 
Since two characters are always the brackets, the decimal number is then 
1-3 characters.

The Facility and Severity of a message are numerically coded with 
decimal values.

       Numerical        Facility
          Code
           0             kernel messages
           1             user-level messages
           2             mail system
           3             system daemons
           4             security/authorization messages (note 1)
           5             messages generated internally by syslogd
           6             line printer subsystem
           7             network news subsystem
           8             UUCP subsystem
           9             clock daemon (note 2)
          10             security/authorization messages (note 1)
          11             FTP daemon
          12             NTP subsystem
          13             log audit (note 1)
          14             log alert (note 1)
          15             clock daemon (note 2)
          16             local use 0  (local0)
          17             local use 1  (local1)
          18             local use 2  (local2)
          19             local use 3  (local3)
          20             local use 4  (local4)
          21             local use 5  (local5)
          22             local use 6  (local6)
          23             local use 7  (local7)

        Note 1 - Various operating systems have been found to utilize
           Facilities 4, 10, 13 and 14 for security/authorization,
           audit, and alert messages which seem to be similar.
        Note 2 - Various operating systems have been found to utilize
           both Facilities 9 and 15 for clock (cron/at) messages.


        Numerical         Severity
          Code

           0       Emergency: system is unusable
           1       Alert: action must be taken immediately
           2       Critical: critical conditions
           3       Error: error conditions
           4       Warning: warning conditions
           5       Notice: normal but significant condition
           6       Informational: informational messages
           7       Debug: debug-level messages


Priority is calculated as: (Facility*8) + Severity. After calculating the Priority,
bound it with barckets and its now a PRI. For example a daemon debug would
be (3*8)+7 => 31 Priority, PRI <31>.

=head2 HEADER

The header portion conatains a timestamp and the device name or IP.

=head3 TIMESTAMP

The TIMESTAMP immediately follows the trailing ">" from the PRI.
The TIMESTAMP is separated from the HOSTNAME by single space characters.

The TIMESTAMP field is the local time and is in the format of 
'Mmm dd hh:mm:ss'. 

    Mmm is the month abbreviation, such as:
    Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec.

    dd is day of month. If numeric day value is a single digit,
    then the first character is a space. This would make the format
    'Mmm  d hh:mm:ss'.

    hh:mm::ss are hour minute seconds, 0 padded. Hours range from
    0-23 and minutes and seconds roange from 0-59.
 
A single space charater must follow the the TIMESTAMP field.

=head3 HOSTNAME

The HOSTNAME is separated from the precedding TIMESTAMP by single 
space characters. The HOSTNAME will be the name of the device as it
knows itself. If it does not have a hostname, then its IP address is
used.

=head2 MSG (message part)

The MSG part will fill the rest of the syslog packet.
The MSG part is made of two parts the TAG and CONTENT.
The TAG value is the name of the originating process and must
not exceed 32 cahracters.
The CONTENT is the details of the message.

=head1 REQUIRES

    Time::Local
    IO::Socket
    Sys::Hostname

=head1 EXPORTS

    parse_syslog_msg
    epoch_to_timestamp
    make_timeslots
    epoch_timeslot_index
    normalize_facility
    normalize_severity

=head1 EXPORT TAGS

    :parser  parse_syslog_msg
    :time    epoch_to_timestamp, make_timeslots, epoch_timeslot_index
    :syslog  normalize_facility, normalize_severity


=head1 Parser Methods and Functions

=head2 parse

Constructor to create object to parse a syslog file's line.
Arguments are used to define parsing. See function parse_syslog_line
section to see how to parse the line.

    ($syslog, $error) = Net::Dev::Tools::Syslog->parse(
        -dump        =>  <directory>,
        -append      =>  <0|1>,
        -ext         =>  <extension>,
        -report      =>  <0|1>,
        -interval    =>  <seconds>,
        -debug       =>  <0|1|2|3>,
        -rx_time     =>  <0|1>,
        -lastmsg     =>  <0|1>,
        -min_date    =>  <mm/dd/yyyy [hh:mm]>,
        -max_date    =>  <mm/dd/yyyy [hh:mm]>,
        -device      =>  <pattern>,
        -tag         =>  <pattern>,
        -message     =>  <pattern>,

    );


Argument Checks:

If -dump is used, then argument must be a directory, current
directory is not assumed. The directory provided must exist and
allow user write access. If -interval is less than 60, it is set to 60.
If -min_date and/or -max_date are given there syntax and range are checked.


Return, in list context will return reference to object and error.
In scalar context returns reference to object.


=over 4

=item -dump <directory>

    Enable creation of separate syslog files. Each file created will only
    contain lines for the device defined in the syslog message. 
    The <directory> argument define a directory to where device specific 
    syslog files are dumped. Current directory is not assumed.
    Directories are checked for existence and writability.

    Default = FALSE, no dumps
 
=item -append <0|1>

    If 0, device files created due to -dump are overwritten.
    If 1, device files created due to -dump are appended to.
    Default = 0, (overwrite)

=item -ext <extension>

    File extension to use for device files created due to -dump
    being enabled.
    Default = 'slp', (SysLog Parsed)

=item -report <0|1>

    If 0 no data is stored in the object.
    If 1 data is stored. For each line successfully parsed, information
    is pushed on to @DATA. See Data Access section for access information.
    Default = 1

=item -interval <seconds>

    The amount of seconds to use when making timeslots. 
    make_timeslots function will make timeslot ranging from
    min and max time found or given. The timeslot info can then
    be used to create stats for desired time intervals.
    See @TIMESLOTS for more info.
    Min value is 60 (1 minute).
    Default is 3600 (1 hour).

=item -debug  <0|1|2|3>

   Set debug level, verbosity increases as number value increases.


=item -rx_time <0|1>

   Set flag to use the receive time and not the timestamp from the
   sylog message. Some syslog deamon prepend information to the syslog
   message when writing to a file. If a receive time is one of these
   fields, then it can be used. This will normalize all times to when
   they are received by the serever.
   Default is 0

=item -lastmsg  <0|1>

   Set flag to to handle last message as previous message.
   If true and the syslog message has the pattern 
   'last message repeated N time',then we replace this current
   line with the previous line. Otherwise the 'last message' line
   is treated as all other syslog lines. The tag will be defined as
   'lastmsg', pid and content set to ''.
   Default is 0.


=item -min_date <mm/dd/yyyy [hh:mm::ss]>

   If given, then will be used to filter dates. Only lines with dates
   greater to or equal to this will be be parsed. This check is performed
   after -rx_time, thus filter applies to whatever date you decide to keep.

   You must enter mm/dd/yyyy, other values will default:
      ss defaults to 0 if hh:mm given, 59 if no time given
      mm defaults to 0 if hh: given, 59 if no time given
      hh defaults to 23 if no time given

   Mmm/dd/yyyy can als be use, where Mmm is Jan, Feb, Mar,...


=item -max_date <mm/dd/yyyy [hh:mm::ss]> 

   If given, then will be used to filter dates. Only lines with dates
   less than or equal to this will be be parsed. This check is performed
   after -rx_time, thus filter applies to whatever date you decide to keep.

   Apply same syntax rules as -min_date

=item -device <pattern>

    If given, only device fields matching the pattern are kept. Text strings
    or Perl regexp can be given.


=item -tag <pattern>

    If given, only tag fields matching the pattern are kept. Text strings
    or Perl regexp can be given.

=item -message <pattern>

    If given, only message fields matching the pattern are kept. Text strings
    or Perl regexp can be given.


=back


=head2 &parse_syslog_line

    ($parse, $error) = $syslog->parse_syslog_line(<line>);

Method to parse the syslog line. If syslog line <line> is not given 
as argument then $_ is parsed.

Some syslog daemons may prepend other information when writing 
syslog message to syslog file. &parse_syslog_line will detect this
by applying a regexp match for an RFC 3164 syslog message. The match
will be treated as the syslog message, any string found before the 
match will be considered a preamble. The preamble will be parsed for
receive time, syslog priority (facility.severity) and source IP address.
This info is avaliable to the user.

This function also assumes all lines contain a 'tag' as described
in RFC 3164. If a syslog message does not contain a tag then the hash
key tag ( $hash{tag} ) is set to 'noTag'. A tag is not assumed to have a 
PID as described by the RFC. For tag's not containing a PID, $hash{pid} = ''.
If a syslog message is  '... last line repeated N time', then
$hash{tag} is set to 'lastmsg'.

$parse_syslog_line calls &parse_syslog_msg and &parse_preamble to
parse respective information. Any facility or severity parsed is 
normalized to the stings listed in @FACILITY and @SEVERITY. 

Syslog messages are the stings matched by $SYSLOG_msg. Changing
this string to something else allows the user to modify the parser.


See Data Access Section for hash access.

In list context a reference to a hash and error are returned.
In scalar context, a reference to a hash is returned.

Events to Return Error:

=over 

=item  blank line

=item  device name is not parsed

=item  outside of date range, if date filters are applied

=item  no date parsed and date filters are applied

=item  unable to dump line to file, if -dump option true

=back


=head1 Send Methods and Functions

=head2 send

Constructor to create object that will send syslog messages from localhost.
Arguments define all portions of a RFC 3164 Syslog message. Message is sent
when &send_msg is called.

Any argument can be defined now or when &send_msg is called. This allows the user
to set values that are static for their needs or change dynamically each time
a message is sent.

    ($syslog, $error) = Net::Dev::Tools::Syslog->send(
        -server    =>   <server IP>,
        [-port      =>  <destination port>,]
        [-proto     =>  <udp|tcp>,]
        [-facility  =>  <facility string>,]
        [-severity  =>  <severity string>,]
        [-timestamp =>  <message timestamp>,]
        [-device    =>  <device name>,]
        [-tag       =>  <tag>,]
        [-pid       =>  <tag PID>,]
        [-message   =>  <syslog message>,]
        [-strict    =>  <0|1>,]
    );


=over

=item -server

Destination Syslog Server IP Address. Default 127.0.0.1

=item -port

Destination Port. Default is 514.

=item -proto

IP protocol to use, default is udp.

=item -facility

Syslog Facility to use. Default is 'user'.

=item -severity

Syslog Severity to use. Default is 'debug'.

=item -timestamp

Timestamp to put in to syslog message. Default is current time.

=item -device

Device name to put in to syslog message. Default is $HOSTNAME

=item -tag

Syslog message tag. Default is NetDevSyslog.

=item -pid

Syslog message tag PID, enlcosed in '[' ']'. Default is 1.

=item -strict

By default strict syntax is enforced, this can be disabled with -strict.
Strict rules allow message to be no longer than 1024 and tag within message 
to be no longer than 32.

=back


=head2 send_msg

Function will create a RFC 3164 syslog message and send to destination IP:port.
For values not defined by user, defaults will be used. The same arguments given
for the constructor 'send' apply to this function. Thus any value can be changed
before transmission. 

    ($ok, $error) = $syslog->send_msg(
        [-server    =>   <server IP>,]
        [-port      =>  <destination port>,]
        [-proto     =>  <udp|tcp>,]
        [-facility  =>  <facility string>,]
        [-severity  =>  <severity string>,]
        [-timestamp =>  <message timestamp>,]
        [-device    =>  <device name>,]
        [-tag       =>  <tag>,]
        [-pid       =>  <tag PID>,]
        [-message   =>  <syslog message>,]
        [-strict    =>  <0|1>,]
    );

For any error detected, the message will not be sent and undef returned.
For each message sent, the socket is opened and closed.
If message is sent, '1' is returned.

=head1 Listen Methods and Functions

=head2 listen

Constructor to create object that listens on desired port and prints out
messages received. Message are assumed to be syslog messages.

    ($syslog, $error) = Net::Dev::Tools::Syslog->listen(
        [-port       => <port>,]
        [-proto      => <udp|tcp>,]
        [-maxlength  => <max message length>,]
        [-packets    => <integer>],
        [-verbose    => <0|1|2>,]
        [-report     => <0|1>],
    );


Message received will be printed to STDOUT.

CTRL-C will shutdown the socket and return control back to caller.

If -report option is enabled, then a reference to object that can be
used to access @DATA and populate %STATS will be returned. 

Otherwise a counter value indicating a message received  is returned.


=over

=item -port

Local port to listen for messages. Messages are assumed to be syslog messages.
Some OS's may require root access.
Default is 514.

=item -proto

Protocol to use. 
Default is udp.


=item -maxlength

Max message length. Default is 1024

=item -packets

Shutdown socket listening on after N packets are received on the
given port. At least one packet must be received for packet count
to be checked. 

=item verbose

Verbosity level

=item report

Perform same reporting as the parse method does. All arguments to the parse
method can be used on this method. Unlike the parse method, reporting
is off by default for listen method.


=back




=head1 General Functions

=head2 init

Initialize the hash storing the current syslog line information.

    $syslog->init();


=head2 close_dumps

Function to loop through all filehandles opened for dumping a syslog
line to a device specific file.

    $syslog->close_dumps();


=head2 syslog_stats

Function to loop through @DATA and create %STATS.
%STATS is a complex data structure storing statistics of the current 
syslog file. See Data Access section.


   $stat_ref = $syslog->syslog_stats(
         [min  => <mm/dd/yyy [hh:mm:ss]>],   # min date
         [max  => <mm/dd/yyy [hh:mm:ss]>],   # max date
   );


=head2 epoch_to_timestamp

Function to convert epoch seconds to a RFC 3164 syslog message timestamp.
If epoch seconds not given, then current time is used.

   $timestamp = epoch_to_timestamp($epoch);

=head2 epoch_to_datestr

Function to convert epoch seconds to a common date string.
If epoch seconds not given, then current time is used.

   $date_str = epoch_to_datestr($epoch)

Date string format  Mmm/dd/yyyy hh:mm:ss

=head2 date_filter_to_epoch

Function to convert date given for a filter to epoch seconds.

   $epoch = date_filter_to_epoch(<mm/dd/yyyy [hh:mm:ss]>);

=head2 validate_timestamp_syntax

Function to validate that a given timestamp matches the syntax
defined by RFC 3164. If valid, then '1' is returned, if invalid
then '0' is returned.

   $ok = validate_timestamp_syntax($timestamp);

=head2 make_timeslots

Function to create @TIMESLOTS given the min/max epoch seconds and
the interval. Will start at min epoch value and increment until
reaching or exceeding the max epoch value. For each increment an
index is made based on the min epoch for that interval. The index
is created with &epoch_to_datestr.

    make_timeslots($min_epoch, $max_epoch, $interval);

Min and max values are mandatory and are checked to be greater or less
than the other value. If $interval is not given, function defaults
to 60 seconds.

The created list is built as such

    @TIMESLOTS = ([$index, min_epoch, $max_epoch], ...);

This list can be used to group syslog messages to a specific timeslot.
From the syslog line we have epoch seconds, this list provides a range
to check the epoch seconds against and the index for that range.

=head2 epoch_timeslot_index

Function that takes a given epoch second value and returns the timeslot
index value for that value from @TIMESLOTS.

    $index = epoch_timeslot_index($epoch);

If no match is found, undef is returned.

=head2 normalize_facility

Function to take a character string representing a facility and 
return a normalize string contained in @FACILITY.

   $facility = normalize_facility($facility);

If given string is not normailized, it is returned

=head2 normalize_severity

Function to take a character string representing a severity and 
return a normalize string contained in @SEVERITY.

   $severity = normalize_severity($severity);

If given string is not normailized, it is returned

=head2 decode_PRI

Function to decode PRI in decimal format to a Facility and Severity.
Can accept either decimal number or decimal number bounded by '<' '>'.

In list context will return lis tof information, in scalar context will
return respective Facility and Severity strings joined with '.'.


   @pri = decode_PRI($pri_dec);
   $PRI = decode_PRI($pri_dec);

   $pri[0]  PRI decimal value
   $pri[1]  Facility decimal value
   $pri[2]  Severity decimal value
   $pri[3]  PRI character string (join facility and severity string) 
   $pri[4]  Facility charater string
   $pri[5]  Severity charater string

Given PRI value is checked to be between 0 and 191. If not, then undef
is returned in scalar context and for list values any decimal
number is -1, P?, F?, S? for PRI, Facility Severity character strings
respectively


=head2 set_year

Set the value used by methods and functions of this module to the current
year as known by localtime.  Syslog message timestamps do not conatain year
information. A user may need to change this when looking a a syslog from 
a different year.

If no value is given, then the current year is assumed, otherwise
the year is set to the argument.

   $syslog->set_year(2003);   # set year to 2003
   $syslog->set_year();       # set year to ((localtime)[5]) + 1900


=head2  data_aref

Return reference to @DATA.

=head2 stats_href

Return reference to %STATS 

=head2 device_aref

Return reference to @DEVICES

=head2 facility_aref

Return reference to @FACILITY

=head2 severity_aref

Return reference to @SEVERITY

=head2 tag_aref

Return reference to @TAGS

=head2 timeslot_ref

Return reference to @TIMESLOTS

=item error

Return last error.



=head1  Data Access

=head2 @FACILITY

List of all syslog facilities strings as defined by RFC 3164.
Any facility string parse or given by the user is normalized 
to strings found in this list. 

=head2 @SEVERITY

List of all syslog severities strings as defined by RFC 3164.
Any severity string parse or given by the user is normalized 
to strings found in this list. 

=head2 %Syslog_Facility

Hash whose keys are syslog facility strings and whose value
is the decimal representation of that facility.

=head2 %Syslog_Severity

Hash whose keys are syslog severity strings and whose value
is the decimal representation of that severity.


=head2 $SYSLOG_msg

The pattern used to parse any RFC 3164 syslog message.


=head2 Syslog Line Hash Reference (parse_syslog_line)

The hash reference returned by function parse_syslog_line has
the following keys:

    $hash_ref->{line}      current line from syslog file
               {timestamp} timestamp from syslog message
               {device}    device name from syslog message
               {message}   syslog message, from after devname
               {month_str} month from syslog message timestamp (Jan, Feb, ..) 
               {month}     month index 0->11
               {day}       day from syslog message timestamp
               {time_str}  hh:mm:ss from syslog message timestamp
               {hour}      hh from syslog message timestamp
               {min}       mm from syslog message timestamp
               {sec}       ss from syslog message timestamp
               {year}      year assumed from localtime
               {epoch}     epoch time converted from syslog message timestamp
               {wday}      wday integer derived from epoch (0-6) = (Sun-Sat)
               {wday_str}  wday string converted, (Sun, Mon, ...)
               {date_str}  syslog message {epoch} convert to common format
               {tag}       syslog message content tag
               {pid}       syslog message content tag pid
               {content}   syslog message content after tag parsed out
               {preamble}     fields prepended to syslog message
               {rx_epoch}     extra info: rx time epoch
               {rx_timestamp} extra info: rx timestamp
               {rx_priority}  extra info: priority (text)
               {rx_facility}  extra info: syslog facility (text)
               {rx_severity}  extra info: syslog severity (text)
               {srcIP}        extra info: src IP address
               {rx_epoch}     extra info: rx time epoch
               {rx_date_str}  extra info: rx time date string
               {rx_time_str}  extra info: rx time (hh:mm:ss)
               {rx_year}      extra info: rx time year value
               {rx_month}     extra info: rx time month value
               {rx_month_str} extra info: rx time month value string (Jan, Feb,..)
               {rx_day}       extra info: rx time day value
               {rx_wday}      extra info: rx time weekday (0-6) (Sun, Mon,..)
               {rx_hour}      extra info: rx time hour value
               {rx_min}       extra info: rx time minute value
               {rx_sec}       extra info: rx time second value

 

=head2 @DATA

@DATA is a array of hashes. Each @DATA element is a hash whose
keys hold info for each line successfully parsed. @DATA is 
populated when -report set to 1.

    @DATA = ( {  timestamp   => <timestamp from syslog message>,
                 epoch       => <timestamp converted to epoch seconds>,
                 device      => <device name from syslog message>,
                 rx_time     => <received timestamp>,
                 rx_epoch    => <rx_time converted to epoch seconds>,
                 rx_priority => <received priority>,
                 rx_facility => <received facility>,
                 rx_severity => <received severity>,
                 rx_srcIP    => <received src IP>,
              }, ...
    );

=head2 %STATS

Multi-level hash that store statisticis from information stored in @DATA.
This hash is created with &syslog_stats and should be considered a 
convienience function to gather stats.
This only represent some basic stats that I thought everyone would want. 
A user can derive their own by looping through @DATA or examining the
the different fields in hash reference returned by &parse_syslog_line.

   All of the values listed below are incremented (counter).
   Strings enclosed in '<' '>' denote keys derived from information
   found in the syslog file.

    $STATS{syslog}{messages} 
                  {min_epoch}
                  {max_epoch}
                  {min_date_str}
                  {max_date_str}
                  {tag}{<tag>}{messages}
                  {facility}{<rx_facility>}{messages}
                  {severity}{<rx_severity>}{messages}


   $STATS{device}{<dev>}{messages}
                        {min_epoch}
                        {max_epoch}
                        {min_date_str}
                        {max_date_str}
                        {tag}{<tag>}{messages}
                        {facility}{<rx_facility>}{messages}
                        {severity}{<rx_severity>}{messages}


=head2 @TIMESLOTS

@TIMESLOTS is a list of time intervals ranging from the min
to max value provided to &make_timeslots function.
A @TIMESLOTS element contains 3 values
 
    @TIMESLOTS = ([index, min_epoch, max_epoch], ...);

       index - Unique string created to indicate start of timeslot
               Mmm/dd/yyyy hh:mm
       min_epoch - is begining of the timeslot interval in epoch seconds.
       max_epoch - is ending of the timeslot interval in epoch seconds.


=head2 @DEVICES

List of devices found. Created when -report is true. When a device
is firsted learned, its device name as known from the sylog message
is pushed on to this list.

=head2 @TAGS

List of tags found. Created when -report is true. When a tag
is firsted learned, its name as known from the sylog message
is pushed on to this list.



=head1 AUTHOR

    sparsons@cpan.org

=head1 COPYRIGHT

    Copyright (c) 2004 Scott Parsons All rights reserved.
    This program is free software; you may redistribute it 
    and/or modify it under the same terms as Perl itself.


=cut




/*
 * SSHswitch.c (u.blanxd.sshswitch)
 *
 * Copyright (c) 2023-06 Blanxd.H <blanxd.h@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** Program return codes
 * 10	setuid error
 * 11	check_status() waitpid() error
 * 12	check_status() posix_spawn() error
 * 13	switch_onoff() waitpid() error
 * 14	switch_onoff() posix_spawn() error
 * 15	unknown argument given (before v.1.1.0: cannot read /etc/ssh/sshd_config)
 * 16	cannot read the plist (before v.1.1.0: cannot write /etc/ssh/sshd_config.tmp)
 * 17	cannot find launchctl binary
 * 18	cannot read /etc/ssh/sshd_config (v.0.4-v.1.0.1: unknown argument given)
 * 19	cannot write /etc/ssh/sshd_config.tmp (v.1.0-1.0.1: cannot read the plist)
 * 20	cannot rename /etc/ssh/sshd_config to /etc/ssh/sshd_config.b
 * 21	cannot write /etc/ssh/sshd_config (or cannot "rename" /etc/ssh/sshd_config.tmp to it)
 * 22-29 reading prefs errors
 * 30-40 writing prefs errors
 * 41-44 v.1.0: plist writing errors
 **/

#include <dlfcn.h>
#include <stdio.h> // snprintf, vsprintf, fopen etc..
#include <unistd.h> // access() getpid() chown()
#include <asl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h> // O_RDONLY, open() and friends
#include <string.h> // strerror()
#include <ctype.h> // isdigit() tolower()
#include <libgen.h> // dirname() basename()
#include <stdarg.h> // for my log func (va_start & friends)
#include <sys/stat.h>  // stat, mkdir, chmod
#include <sys/time.h>  // utimes, gettimeofday
#include <signal.h> // kill
#include <utmpx.h> // utmpx stuff
#include <sys/sysctl.h> // for finding args of process
#include <pwd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <CoreFoundation/CFNotificationCenter.h>
#include <CoreFoundation/CFString.h>

/**
 * this one probably isn't included in your everyday iOS SDKs nor ${THEOS}/vendor/include/ by default
 * libproc.h also depends on (found in the /bsd/ subdir):
 * <sys/proc_info.h>
 * <sys/kern_control.h>
 * <sys/_types/_u_char.h>
 * <net/route.h>
 * look for them (and see the licenses there) in
 * 	https://opensource.apple.com/source/xnu/ or https://github.com/apple-oss-distributions/xnu/
 * 	https://opensource.apple.com/source/xnu/bsd/ or https://github.com/apple-oss-distributions/xnu/bsd/
 * it's sort of `mkdir -p ${THEOS}/vendor/include/libsyscall/wrappers/libproc ${THEOS}/vendor/include/sys/_types ${THEOS}/vendor/include/net`
 *  then put the files into these dirs
 **/
#include <libsyscall/wrappers/libproc/libproc.h> // proc_listpids() and friends


/** Electra setuid **/
void electra_patch_setuid() {
    void* ljb_handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
   	if (!ljb_handle){
   		return;
   	}

    dlerror();
    typedef void (*fix_setuid_prt_t)(pid_t pid);
    fix_setuid_prt_t ptr = (fix_setuid_prt_t)dlsym(ljb_handle, "jb_oneshot_fix_setuid_now");

    const char *dlsym_error = dlerror();
    if (dlsym_error){
        return;
    }

    ptr(getpid());
}
/** /END Electra setuid **/

static const char * s_logname = " u.blanxd.sshswitch "; // Blanxd.h logging, the name. Keep spaces around this, easier to insert it everywhere
static uint8_t s_namesize = 20; // with the spaces (without the ending \0)
#define S_SSHD "sshd"
#define S_SSHDID "com.openssh." S_SSHD
#define RL_ROOT "/var/jb" // root directory path. will not be used (stripped from the paths) unless we're rootless.

// file paths
static const char * rl_root = RL_ROOT;
static const char * fp_opensshdc = RL_ROOT "/etc/ssh/sshd_config";
static const char * fp_opensshdp = RL_ROOT "/Library/LaunchDaemons/" S_SSHDID ".plist";
static const char * const fp_tweakpref = "/var/mobile/Library/Preferences/u.blanxd.sshswitch/prefs";
// backward compatibility (pre v.1.1.0) prefs files
static const char * fp_letemling = "/etc/ssh/u.blanxd.sshswitch.letemlinger";
static const char * fp_evenlockd = "/etc/ssh/u.blanxd.sshswitch.eveniflocked";
static const char * fp_notonboot = "/etc/ssh/u.blanxd.sshswitch.notonboot";
static const char * fp_bootastog = "/etc/ssh/u.blanxd.sshswitch.bootastog";
// program paths
static const char * pp_launchctl = RL_ROOT "/bin/launchctl"; // default (Ele,u0,Chi,procursus), checkra1n has it in /sbin
static const char * pp_launchctls = "/sbin/launchctl"; // checkra1n has it in /sbin

// Like in Dopamine 1.1 (https://github.com/opa334/Dopamine/)
// https://raw.githubusercontent.com/opa334/Dopamine/23ae3723f8c4812d05ac3ad83aa03db53e855359/BaseBin/systemhook/src/common.h
// But trying to get away with the smallest possible size instead of PATH_MAX (=1024),
// and only using it if nothing else resolves, once for each of the paths, in main(). See the func paths().
#define JB_ROOT_PATH(path) ({ \
  uint16_t len = strlen(rl_root) + strlen(path) + 1; \
  char *outPath = alloca(len); \
  strlcpy(outPath, rl_root, len); \
  strlcat(outPath, path, len); \
  (outPath); \
})

// some repeated stuff
static const char * const s_pt = "Port ";
static const char * const s_la = "ListenAddress ";
static const char * const s_pr = "PermitRootLogin ";
static const char * const s_pa = "PasswordAuthentication ";
static const char * const s_ca = "ChallengeResponseAuthentication "; // if we encounter this, just comment it out (and use KbdInteractiveAuthentication if needed)
static const char * const s_ki = "KbdInteractiveAuthentication "; // the server supports SSHv2 only anyway, and this keyword is supported since at least ver.4.8 (2008-03-31 ie. before iPhone OS 2). Ver.7.6 was bundled with Electra ie. 1st jb iOS 11. Saurik I guess 1st packaged maybe ver.5.9 or so.
static const char * const s_up = "UsePAM ";
static const char * const s_ka = "PubkeyAuthentication ";
static const char * const s_ta = "AuthenticationMethods ";
static const char * const s_ak = "publickey";
static const char * const s_ap = "password";
static const char * const s_ai = "keyboard-interactive";
static const char * const s_ys = "yes";
static const char * const s_no = "no";

// runtime global stuff
static aslclient g_aslc = NULL; // used if any error logging occurs
static uint8_t g_isindsshd = 0; // 0=unknown, 1=sshd(Electra/early Chimera/...), 2=launchd(Unc0ver/Checkra1n/...)
static uint8_t g_forcekick = 0; // 0=not set, 1=let 'em Linger, 2=kick 'em
static FILE * ff_opensshdp = NULL; // global pointer to fopen(fp_opensshdp,"r");
static FILE * ff_tweakpref = NULL; // global pointer to fopen(fp_tweakpref,*);

// our prefs, gotten or being written to our prefs file
static char g_pref_rnb[2] = {'0',0}; // "0"=not read yet, else either "r"/"n"/"b".
static char g_pref_ef[2] = {'0',0}; // "0"=not read yet, else either "e"/"f".
static char g_pref_kl[2] = {'0',0}; // "0"=not read yet, else either "k"/"l".
static char g_pref_oo[64] = {'0',0}; // "0"=not read yet, else possibly like "off 12345,12345,12345,12345,12345,12345,12345,12345 a1 w1 u1 g1", "-" means the pref hasn't been saved yet or some internal error.

static void
bhLog(const char *format, ...){

	struct timeval tv;
	gettimeofday(&tv, NULL);

	// prepending the ts and name to the format
	char f[ strlen(format)+s_namesize+16 ]; // 16=( 10=tv_sec until 9999999999(Nov.2286) + 1=dot + 4=millis + 1=\0 )
	snprintf(f, 16, "%ld.%04d", tv.tv_sec, tv.tv_usec/100);
	strncat(f, s_logname, s_namesize);
	strlcat(f, format, strlen(format)+s_namesize+16);

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	if ( !g_aslc )
		g_aslc = asl_open(NULL, "com.apple.console", ASL_OPT_STDERR | ASL_OPT_NO_DELAY);

	va_list argp;
	va_start(argp, format);
	asl_vlog(g_aslc,NULL,ASL_LEVEL_ERR,f,argp);
	va_end(argp);
	//asl_close(g_aslc); // in finish_cleanup()
#pragma clang diagnostic warning "-Wdeprecated-declarations"

}

// 1:exists, 0:don't exist/cannot stat
static _Bool
is_file(const char *path) {
	if ( access( path, F_OK ) != -1 )
		return 1;
	return 0;
}

// dotouch:0/(>=1) = whether to remove or touch, pathname = path name.
// return 0 if all cool, >0 if some error. 1=cannot create, 2=cannot set mtime, 3=cannot delete
static uint8_t
touchremove(int dotouch, const char* pathname){
	if ( dotouch>0 ){
		// http://chris-sharpe.blogspot.com.ee/2013/05/better-than-systemtouch.html
		int fd = open(pathname, O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666);
		if (fd<0){
			return 1;
		}
		int rc = utimes(pathname, NULL);
		if (rc){
			return 2;
		}
	} else {
		if ( !is_file(pathname) ){
			return 0;
		}
		if ( remove( pathname ) != 0 )
			return 3;
	}
	return 0;
}

// paths are dynamic as of v.1.1.0
static int
paths() {

	size_t rlen = strlen(rl_root);

	const char * rooted = fp_opensshdc;
	rooted += rlen;

	_Bool is_rooted = is_file(rooted);
	_Bool ok_varjb = ( !is_rooted && !is_file(fp_opensshdc) )
		? 0
		: 1;

	if ( is_rooted || !ok_varjb ){

		fp_opensshdc += rlen;
		fp_opensshdp += rlen;
		pp_launchctl += rlen;

		rl_root = ok_varjb ? "" : getenv("JB_ROOT_PATH");

	}

	if ( !is_file( ok_varjb ? pp_launchctl : JB_ROOT_PATH(pp_launchctl) ) ){
		// so if cannot find in /bin (Procursus installs it in /usr/bin but makes a link in /bin so it's ok)
		pp_launchctl = pp_launchctls;
		if ( !is_file(pp_launchctl) ){
			return 0;
		}
	}

	return ok_varjb ? 1 : 2;
}

#pragma mark helpers for strings and stuff

static _Bool
arg_no(char * arg){
	return ( arg[0] == '0' || arg[0] == 'n' ) ? 1 : 0;
	// an empty string (a '\0') also means "yes", and a `skip' dash ("-") is not a "no"
}
/* not even trying, anything not '0' or 'n', or `-', means yes, even /nothing/ ie. instant '\0' *
static _Bool
arg_yes(char * arg){
	return ( arg[0] == '1' || arg[0] == 'y' ) ? 1 : 0;
}
**/
static _Bool
arg_skip(char * arg){
	return arg[0] == '-' ? 1 : 0;
}

static char *
ltrim(char * s, char * w)
{
	char * r = s;
	r += strspn(s,w);
	return r;
}

// return new pointer to the 1st non-whitespace character
static char *
ltrim_ws(char * s)
{
	return ltrim(s," \t");
}

// so it's 1=true, 0=false
static _Bool
in_array(uint16_t needle, uint16_t* haystack, size_t max){
	if ( max == 0 ) return 0;
	for(size_t i=0; i<max; i++)
		if ( needle == haystack[i] )
			return 1;
	return 0;
}

//// TODO?: okport() functionality might as well be included in ports_split()
// 1=ok, 0=not
static _Bool
okport(int nport){
	return ( nport == 22 ||
				( nport < UINT16_MAX && nport > 1000

					// lsof +c20 -nP | grep LISTEN
					// for i in /System/Library/LaunchDaemons/*plist; do plutil $i | grep SockServiceName && echo "^ $i"; done
					// (if their SockType is "dgram" then never mind it's UDP, else can grep for the named ones in /etc/services)

					&& nport != 1080 // /System/Library/LaunchDaemons/com.apple.PurpleReverseProxy.plist (localhost)
					&& nport != 1083 // /System/Library/LaunchDaemons/com.apple.PurpleReverseProxy.plist (localhost)
					&& nport != 8021 // /System/Library/LaunchDaemons/com.apple.ftp-proxy-embedded.plist
					&& nport != 62078 // /System/Library/LaunchDaemons/com.apple.mobile.lockdown.plist
				)
			) ? 1 : 0;
}

// populate nports and return the amount populated (the rest should be considered undefined/not guaranteed)
static int8_t
ports_split(char* cports, uint16_t *nports, size_t max_ports, _Bool any){

	int8_t cnt = 0;
	if ( max_ports > INT8_MAX ) max_ports = INT8_MAX;
	int clen = strlen(cports);
	char prt[6];
	uint32_t iprt; // 5 chars might give us a bigger number than allowed (uint16_t for port numbers)
	uint8_t nri = 0;
	int i;

	for( i=0; i<=clen && cnt<max_ports; i++ ){
		if ( cports[i] == ',' || cports[i] == '\0' || nri >= 5 ){
			prt[nri] = '\0';
			iprt = (uint32_t)strtol(prt, NULL, 10); // (uint32_t)atoi(prt) // no need for error checking with 5 chars
			if ( (any==1 || okport(iprt)==1) && in_array(iprt,nports,cnt)==0 ){
				nports[cnt] = iprt;
				cnt++;
			}
			nri = 0;
		} else if ( isdigit(cports[i]) != 0 ) {
			prt[nri] = cports[i];
			nri++;
			if ( nri==5 && i<cnt ) // got past 5 chars but no comma so let's register this as the 1st of the next sequence. unless it's the end.
				i--;
		}
	}
	return cnt;
}

// create comma separated ports list
// dest must be big enough to hold it all ie. (max_ports*5 + max_ports). eg. char[48] for 8 ports.
// not doing more than 8. //// TODO: global max_ports or something
// not checking for port numbers' sanity much, this must have been done already.
static _Bool
ports_implode( uint16_t *ports, size_t max_ports, char * dest ){

	char * ret = dest;
	size_t tst_len = 0;
	uint16_t addlen = 0;
	ret[0] = '\0';
	if ( max_ports>8 ) max_ports = 8; //// TODO: global max_ports or something
	for (int8_t i=0; i<max_ports; i++){
		if ( ports[i] > 9999 ) addlen = 6;
		else if ( ports[i] > 999 ) addlen = 5;
		else if ( ports[i] > 99 ) addlen = 4;
		else if ( ports[i] > 9 ) addlen = 3;
		else if ( ports[i] > 0 ) addlen = 2;
		else continue;
		tst_len += addlen;
		if ( tst_len > max_ports*5 + max_ports )
			break; // so this one won't fit
		if ( i>0 ){
			ret[0] = ',';
			ret += 1;
		}
		if ( snprintf(ret, addlen, "%d", ports[i]) >= addlen ){
			return 0;
		}
		ret += addlen-1;
	}
	if ( dest[0] == '\0' )
		return 0;
	return 1;
}

// overall /end of run/ cleanup. Close global file pointers, plus some more if told to.
// In addition to our prefs and OpenSSH launchd plist, if given, the pointers of args ifs
// and ofs also get closed, and ofspath, if given, gets deleted.
static int
finish_cleanup(int ret, FILE * ofs, char * ofspath, FILE * ifs){
	if ( ifs != NULL )
		fclose(ifs);
	if ( ofs != NULL )
		fclose(ofs);
	if ( ofspath != NULL )
		touchremove(0, ofspath);
	if ( ff_opensshdp != NULL )
		fclose(ff_opensshdp);
	if ( ff_tweakpref != NULL )
		fclose(ff_tweakpref);
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	if ( g_aslc )
		asl_close(g_aslc);
#pragma clang diagnostic warning "-Wdeprecated-declarations"
	return ret;
}

#pragma mark tweak/tool settings

// 1 = ok
// negative means error
static int8_t
prefs_open( _Bool get_set ){

	if ( ff_tweakpref != NULL ){
		rewind(ff_tweakpref);
		return 1;
	}

	if ( !is_file(fp_tweakpref) ){

		char * fp_dirname = dirname((char *)fp_tweakpref);
		char * fp_filname = basename((char *)fp_tweakpref);

		if ( fp_dirname==NULL || strlen(fp_dirname)==1 || fp_dirname[0]=='.' || fp_filname==NULL || fp_filname[0]=='/' || fp_filname[0]=='.' ){
			return -24;
		}

		if ( !is_file(fp_dirname) ){
			// need to mkdir, chmod 700 chown mobile:mobile. Not going further up than 1 dir though.
			if ( mkdir(fp_dirname, 0700) != 0 ){
				return -27;
			}
			if ( chown(fp_dirname,501,501) != 0 ){
				return -28;
			}
		}

		if ( touchremove(1,fp_tweakpref) > 0 ){
			return -25;
		}
		if ( chown(fp_tweakpref,501,501) != 0 ){
			return -26;
		}
	}

	ff_tweakpref = fopen(fp_tweakpref, get_set ? "r+" : "r");
	if ( ff_tweakpref == NULL ){
		return get_set ? -23 : -22;
	}

	return 1;
} // static int8_t prefs_open( _Bool get_set ){

// populate all OpenSSH settings in one go, based on an /args/ string.
// on/off must be 1st in the string, the rest must be letter prefixed or numbers(&comma) only.
//  any of them could be provided NULL (0 for max_ports) so we don't assign anything there.
// Return the number of ports populated.
//  It could be 0, meaning there were no good ports there (in which case the ports array wasn't touched).
// If any of the stuff is missing from the line, they're set to -1 (unless given NULL). If either w or u exists, am gets a valid value.
static int8_t
prefs_oo_parse_all( char * line, int8_t *oo, uint16_t *ports, size_t max_ports, int8_t *ar, int8_t *am, int8_t *gl ){

	// defaults
	if ( oo != NULL ) *oo = -1;
	if ( ar != NULL ) *ar = -1;
	if ( am != NULL ) *am = -1;
	if ( gl != NULL ) *gl = -1;
	int8_t ap=-1, ak=-1; // should really have one of each but this func actually also works with repetitions (* INT8_MAX-3), the last one of each wins.

	int8_t ti=0, pc=0;
	char *lptr=line, *part;
	size_t len = strlen(lptr), plen, tokslen = 0;
	part = strsep(&lptr, " ");
	while( part != NULL && ti<INT8_MAX ){

		plen = strlen(part);
		if ( // undo strtok damage to the line
			tokslen>0 &&
			tokslen<len
		){
			line[tokslen] = ' ';
			tokslen++;
		}
		tokslen += plen;

		if ( part[0] == '\n' )
			break;

		if ( plen>0 ){

			if ( ti==0 ){
				if ( oo != NULL ){
					if ( part[0]!='o' ) break;
					else if ( part[1]=='n' ) *oo = 1;
					else if ( part[1]=='f' ) *oo = 0;
					else break;
				}
			} else {
				switch(part[0]){
					case 'a': if ( ar != NULL ) *ar = part[1]=='0' ? 0 : 1; break;
					case 'w': if ( am != NULL ) ap = part[1]=='0' ? 0 : 1; break;
					case 'u': if ( am != NULL ) ak = part[1]=='0' ? 0 : 1; break;
					case 'g': if ( gl != NULL ) *gl = part[1]=='0' ? 0 : 1; break;
					default:
						if ( max_ports>0 && ports != NULL && strspn(part,"1234567890,")==plen )
							pc = ports_split(part, ports, max_ports, 0);
				}
			}
			ti++;
		}

		part = strsep(&lptr, " ");
	}
	if ( tokslen>0 && tokslen<len ) // undo strtok damage to the line
		line[tokslen] = ' ';

	if ( ap>-1 || ak>-1 )
		*am = ( ap!=0 && ak!=0 ) ? 0 : ( ap!=0 ? 1 : ( ak!=0 ? 2 : 3 ) );

	return pc;
} // static int8_t prefs_oo_parse_all( char * line, int8_t *oo, uint16_t *ports, size_t max_ports, int8_t *ar, int8_t *am, int8_t *gl ){

// Get a relevant part from the on/off line.
// Return either 1/0 for most requests, for ports populate the ports array and return the amount populated.
// The request should be a letter (we only check for the 1st letter), o|p|a|w|u|t|g.
// For ports ("p"), the ports,max_ports must be sane (not NULL and 0), else they can be NULL,0.
// A -1 return means it wasn't found.
static int8_t
prefs_oo_getone( char * line, char * req, uint16_t *ports, size_t max_ports ){

	int8_t ret, pc;

	pc = prefs_oo_parse_all( line,
		req[0]=='o' ? &ret : NULL,
		ports, max_ports,
		req[0]=='a' ? &ret : NULL,
		strchr("wut",req[0])!=NULL ? &ret : NULL,
		req[0]=='g' ? &ret : NULL
		);

	if ( strchr("wut",req[0]) == NULL )
		return req[0]=='p' ? pc : ret;

	if ( ret < 0 )
		return ret;

	if ( req[0]=='w' )
		return ret==2 ? 0 : 1;

	if ( req[0]=='u' )
		return ret==1 ? 0 : 1;

	return ret==3 ? 1 : 0; // t

} // static int8_t prefs_oo_getone( char * line, char * req, uint16_t *ports, size_t max_ports ){

// populate g_pref_oo
// if max_ports < 1 then only on/off gets written.
// if ar<0 then a isn't written, else it must be like _Bool (0 or 1).
// if am<0 then w and u aren't written, else it must be either 0 for "any", 1 for only pwd, 2 for only key, or 3 for 2fa.
// if gl<0 then g isn't written, else it must be like _Bool (0 or 1).
static _Bool
prefs_oo_compose( _Bool oo, uint16_t *ports, size_t max_ports, int8_t ar, int8_t am, int8_t gl ){

	uint8_t write = 1;
	char cports[48] = {'\0'};

	if ( ports_implode( ports, max_ports, cports ) ){
		write |= 2;
		if ( ar>-1 ) write |= 4;
		if ( am>-1 ) write |= 8;
		if ( gl>-1 ) write |= 16;
	}

	if ( snprintf(g_pref_oo, 64, "o%s", oo==0 ? "ff" : "n")>64 ) return 0;
	if ( (write & 2) && (strlcat(g_pref_oo, " ", 64)>64 || strlcat(g_pref_oo, cports, 64)>64) ) return 0;
	if ( (write & 4) && strlcat(g_pref_oo, ar>0?" a1":" a0", 64)>64 ) return 0;
	if ( (write & 8) && (
			strlcat(g_pref_oo, am>1?" w0":" w1", 64)>64 ||
			strlcat(g_pref_oo, am%2?" u0":" u1", 64)>64 // (am==1||am==3) = (am%2)
		) ) return 0;
	if ( (write & 16) && strlcat(g_pref_oo, gl>0?" g1":" g0", 64)>64 ) return 0;

	return 1;
} // static _Bool prefs_oo_compose( _Bool oo, uint16_t *ports, size_t max_ports, int8_t ar, int8_t am, int8_t gl ){

// change one setting in g_pref_oo
// if the 3rd arg is not NULL, g_pref_oo gets replaced with that one. Else g_pref_oo must be populated beforehand.
// If either pref or val is NULL, the function basically just acts as a check for g_pref_oo (or the 3rd arg).
// pref must start with our settings letters: o p a w u t g. Only the 1st letter matters (except for on/off).
//  if pref starts with "on" or "of" then the val value doesn't even matter (but should not be NULL).
// val is either 0, 1, yes, no. Only the 1st letter matters (except for on/off).
//   For 'o' we check if it's "on" or "of" in the pref 1st, only then if on/off is in val, then for the 0/1/n/y in the val.
//   Or for 'p' the ports, val should be a comma imploded list of numeric ports.
// Return whether success or not.
// in v.1.1.0 only the 'o' option and the NULL,NULL option are actually used, but well this got written so here it is.
static _Bool
prefs_oo_setone(char * pref, char * val, char * from){

	if ( g_pref_oo[0] == '0' || (g_pref_oo[0] == '-' && pref[0] != 'o') ) return 1;

	int8_t oo, ar, am, pc, gl;
	uint16_t ports[8]; //// TODO: global max_ports or something
	pc = prefs_oo_parse_all( from==NULL ? g_pref_oo : from, &oo, ports, 8, &ar, &am, &gl ); //// TODO: global max_ports or something
	if ( oo < 0 && pref[0] != 'o' ) return 0;

	if ( pref != NULL && val != NULL ){
		if ( pref[0] == 'p' ){
			pc = ports_split(val, ports, 8, 0); //// TODO: global max_ports or something
			if ( pc < 1 ) return 0;
		} else {
			switch(pref[0]){
				case 'o':
					if ( strlen(pref) >= 2 ) oo = pref[1]=='n' ? 1 : 0;
					else if ( strlen(val) >= 2 && val[0] == 'o' ) oo = val[1]=='n' ? 1 : 0;
					else oo = arg_no(val) ? 0 : 1;
					break;
				case 'a': ar = arg_no(val) ? 0 : 1; break;
				case 'w':
					if ( arg_no(val) ){
						if ( am<1 ) am=2;
						else if ( am==1 ){
							//// TODO? was "only pwd", and now NOpwd asked. Depends on how we'll go using it...
							am=3;
						}
						//else if ( am==2 ){ /* leave it as was */ }
						else if ( am==3 ) am=2;
					} else {
						if ( am==2 ) am=0;
						else if ( am==3 ) am=1; //// TODO? Depends on how we'll go using it...
					}
					break;
				case 'u':
					if ( arg_no(val) ){
						if ( am<1 ) am=1;
						//else if ( am==1 ){ /* leave it as was */ }
						else if ( am==2 ){
							//// TODO? was "only key", and now NOkey asked. Depends on how we'll go using it...
							am=3;
						}
						else if ( am==3 ) am=1;
					} else {
						if ( am==1 ) am=0;
						else if ( am==3 ) am=2; //// TODO? Depends on how we'll go using it...
					}
					break;
				case 't':
					if ( !arg_no(val) ) am = 3; // yes/1 asked
					else if ( am==3 ) am = 0; // both used to be required so goto `any' mode
					// else there should be no diff, no/0 asked and it was either `any' or one of them
					break;
				case 'g': gl = arg_no(val) ? 0 : 1; break;
			}
		}
	}

	if( !prefs_oo_compose( oo, ports, pc, ar, am, gl ) ) return 0;
	return 1;

} // static _Bool prefs_oo_setone(char * pref, char * val, char * from){

// Return pretty much 0/1 for most requests. < -1 means error.
// All the g_pref_... vars get populated when this is called, with subsequent calls the answers come from those.
// For "p" ie. ports return the amount of ports populated into `ports', then
//  the `ports' and `max_ports' arguments must be sane things (else could be NULL,0),
// For any OpenSSH setting, -1 means no preference ie. use the conf/plist values etc,
//  we're not deciding any defaults here (g_pref_oo is "-").
// Query (the 1st arg) is a letter, almost like the subcommands. The 2nd arg must denote which way
//  we're currently being run (for opening the prefs file correctly).
static int8_t
prefs_get_any( char * pref, _Bool get_set, uint16_t *ports, size_t max_ports ){

	char * search = strspn(pref,"kl")==1
		? "l"
		: ( strspn(pref,"fe")==1
			? "e"
			: ( strspn(pref,"rnb")==1
				? "nb"
				: ( strspn(pref,"opawutg")==1
					? "o"
					: NULL
				)
			)
		);
	if ( search==NULL )
		return -29; // some unimplemented request

	char *g_pref = search[0]=='l'
		? g_pref_kl
		: ( search[0]=='e'
			? g_pref_ef
			: ( search[0]=='n'
				? g_pref_rnb
				: g_pref_oo
				)
			);
	if ( g_pref[0] != '0' ){
		return search[0]=='o'
			? ( g_pref[0] == '-'
				? -1
				: prefs_oo_getone( g_pref, pref, ports, max_ports )
				)
			: ( pref[0]==g_pref[0]
				? 1
				: 0
				);
	}

	int8_t ret;
	if ( (ret = prefs_open( get_set ))<0 )
		return ret;
	ret = 0;

	if ( pref[0] == 'r' )
		ret = 1; // "r" is not a binary toggle so check for either of the other ones
	else if ( search[0]=='o' )
		ret = -1;
	_Bool toolong = 0;

	char istr[65]; // strlen("off 12345,12345,12345,12345,12345,12345,12345,12345 a1 w1 u1 g1\n") = 64
	while ( fgets(istr,65,ff_tweakpref) != NULL ){

		if ( strpbrk(istr,"\n")==NULL ){
			toolong = 1; // skip the next chunks until the line ends
			continue;
		} else if ( toolong==1 ){
			toolong = 0; // next one could be ok
			continue;
		}

		if ( strlen(istr) < 2 )
			continue;

		switch( istr[0] ){
			case 'l':
				g_pref_kl[0] = 'l';
				break;
			case 'e':
				g_pref_ef[0] = 'e';
				break;
			case 'o':
				istr[strcspn(istr,"\r\n")] = '\0'; // strip trailing newline
				if ( strlcpy(g_pref_oo, istr, 64) >=64 )
					return -29; // the error must be here somewhere
				break;
			default:
				if ( strspn(istr,"nb")==1 )
					g_pref_rnb[0] = istr[0];
		}

		if ( strspn(istr,search)==1 ){
			if ( search[0]=='o' ){
				ret = prefs_oo_getone( istr, pref, ports, max_ports );
			} else {
				ret = ret==1
					? 0
					: ( istr[0] == pref[0]
						? 1
						: 0
					);
			}
		}

	} // while ( fgets(istr,65,ff_tweakpref) != NULL ){

	// defaults
	if ( g_pref_kl[0]=='0' ){
		if ( is_file(fp_letemling) ){ // backward compa
			g_pref_kl[0] = 'l';
			if ( pref[0] == 'l' ) ret = 1;
		} else {
			g_pref_kl[0] = 'k';
			if ( pref[0] == 'k' ) ret = 1;
		}
	}
	if ( g_pref_ef[0]=='0' ){
		if ( is_file(fp_evenlockd) ){ // backward compa
			g_pref_ef[0] = 'e';
			if ( pref[0] == 'e' ) ret = 1;
		} else {
			g_pref_ef[0] = 'f';
			if ( pref[0] == 'f' ) ret = 1;
		}
	}
	if ( g_pref_rnb[0]=='0' ){
		if ( is_file(fp_notonboot) ){ // backward compa
			g_pref_rnb[0] = 'n';
		} else if ( is_file(fp_bootastog) ){ // backward compa
			g_pref_rnb[0] = 'b';
		} else {
			g_pref_rnb[0] = 'r';
		}
		if ( search[0] == 'n' )
			ret = ( pref[0]==g_pref_rnb[0] ) ? 1 : 0;
	}
	if ( g_pref_oo[0]=='0' ){
		if ( strlcpy(g_pref_oo,"-",64) >=64 )
			return -29; // the error must be here somewhere
	}

	return ret;

} // static int8_t prefs_get_any( char * pref, _Bool get_set, uint16_t *ports, size_t max_ports ){

// just a coding convenience wrapper
static int8_t
prefs_get( char * pref, _Bool get_set ){
	return prefs_get_any(pref, get_set, NULL, 0);
}

// Writing the given tweak pref or the on/off with ports and all to the pref file as the last line.
// Also setting the relevant global g_pref_... to the appropriate new value.
// Just input the line that needs to get written (mostly a letter).
// Return 0=ok, 1=bad input (or pre conditions), >1 = error. Ie. could be used for final exit status.
// If given the on/off line, it must be either the full line (with at least one port). If the rest is missing they get set to the defaults in g_pref_oo.
//  Or if g_pref_oo is already populated, it could be only one of the settings from that line.
static int8_t
prefs_set( char * pref ){

	int8_t pfo;
	if ( (pfo = prefs_open( 1 ))<0 )
		return -pfo;

	// options are (v.1.1.0)
	// 	sshd settings as the full line (for calling with on/off):
	// 		on ports a? w? u? g?
	// 		off ports a? w? u? g?
	// 	sshd settings separately:
	// 		on / off
	//  	ports
	//  	a?
	//  	w?
	//  	u?
	//  	t?
	//  	g?
	// 	tweaks' settings:
	// 		k / l
	// 		f / e
	// 	launchctl settings:
	// 		r / n / b
	// If new functionality gets added and things get changed, we'd need to keep those for bckwd compa, yeah this isn't good but I'm lazy now.
	//
	// read it, hold the values for a moment locally here, clear and rewrite. The requested thing goes last.

/**
64 = strlen("off 12345,12345,12345,12345,12345,12345,12345,12345 a1 w1 u1 g1\n")
70 = strlen("off 12345,12345,12345,12345,12345,12345,12345,12345 a1 w1 u1 g1
l
e
b
")
**/

	size_t plen = strlen(pref);
	char * npref = pref;
	if ( plen>63 || plen<1 )
		return 1;

	uint8_t forget = ( plen>16 && pref[0]=='o' )
		? 1
		: ( strspn(pref,"kl")==1
			? 2
			: ( strspn(pref,"ef")==1
				? 4
				: ( strspn(pref,"rnb")==1
					? 8
					: 0
				)
			)
		);

	if ( forget<1 ){
		// possibly something from the on/off line?
		// on/off, ports, a? w? u? t? g?

		if ( g_pref_oo[0] == '0' ) return 1;
		if ( g_pref_oo[0] == '-' ){
			// only on/off will work in this case
			if ( pref[0] == 'o' ){
				if ( !prefs_oo_compose( pref[1]=='n', NULL, 0, -1, -1, -1 ) ) return 1;
			} else return 1;
		} else {

			// in v.1.1.0 only the 'o' variant is really used
			if ( strpbrk(pref,"123456789") == pref ){
				pref = "p";
			} else if ( pref[0] != 'o' ) {
				npref += 1;
			}

			if ( strpbrk(pref,"opawutg") == pref ){
				if ( !prefs_oo_setone(pref, npref, NULL) ) return 1;
				npref = g_pref_oo;
				plen = strlen(g_pref_oo);
				forget = 1; // move on as if there were the full on/off line given
			} else
				return 1;

		}
	}

	char preserve[6] = {0};
	if ( forget != 1 ){
		if ( strlcat(preserve, "o", 6) >6 )
			return 34;
	} else if ( strlen(g_pref_oo) != plen || strncmp(npref,g_pref_oo,plen) !=0 ){ // update the global, only if it differs
		// take it apart and glue it back together so we're sure it's good
		if ( !prefs_oo_setone(NULL, NULL, pref) ) return 1;
	}
	if ( forget != 2 ){
		if ( strlcat(preserve, "l", 6) >6 )
			return 35;
	} else if ( g_pref_kl[0] != pref[0] ){
		g_pref_kl[0] = pref[0];
	}
	if ( forget != 4 ){
		if ( strlcat(preserve, "e", 6) >6 )
			return 36;
	} else if ( g_pref_ef[0] != pref[0] ){
		g_pref_ef[0] = pref[0];
	}
	if ( forget != 8 ){
		if ( strlcat(preserve, "nb", 6) >6 )
			return 37;
	} else if ( g_pref_rnb[0] != pref[0] ){
		g_pref_rnb[0] = pref[0];
	}

	uint8_t found = 0;
	uint8_t check = 0;
	_Bool toolong = 0;
	char old[69] = {0}; // the max we hold from the old contents is 70-2

	char istr[65];
	while ( fgets(istr,65,ff_tweakpref) != NULL ){

		if ( strpbrk(istr,"\n")==NULL ){
			toolong = 1; // skip the next chunks until the line ends
			continue;
		} else if ( toolong==1 ){
			toolong = 0; // next one could be ok
			continue;
		}

		check = ( istr[0]=='o' && (istr[1]=='n' || istr[1]=='f') )
			? 1
			: ( istr[0]=='l'
				? 2
				: ( istr[0]=='e'
					? 4
					: ( strspn(istr,"nb")==1
						? 8
						: 0
					)
				)
			);
		if ( check<1 || check==forget )
			continue;

		if ( strspn(istr,preserve)>0 && !(found & check) ){
			if ( strlcat(old, istr, 69) >=69 )
				return 33; // so if this happens the file contents is probably f*d
			found |= check;
		}

		if ( found>13 )
			break;

	} // while ( fgets(istr,65,ff_tweakpref) != NULL ){

	if ( (ff_tweakpref = freopen(NULL,"w+",ff_tweakpref)) == NULL )
		return 30;

	if ( strlen(old)>0 && fputs(old,ff_tweakpref) == EOF )
		return 31;

	if ( strspn(npref,"kfr")<1 ){ // tweak defaults
		if ( fprintf(ff_tweakpref,"%s\n",npref) <0 )
			return 32;
	}

	// remove prefs of older versions of this tool
	if ( forget==2 ){
		touchremove(0,fp_letemling);
	}
	else if ( forget==4 ){
		touchremove(0,fp_evenlockd);
	} else if ( forget==8 ){
		touchremove(0,fp_bootastog);
		touchremove(0,fp_notonboot);
	}

	return 0;

} // static int8_t prefs_set( char * pref ){

#pragma mark launchctl and such

// return 0:notRunning, 1:running, <0:Error
static int
check_status() {

	posix_spawn_file_actions_t action;
	posix_spawn_file_actions_init(&action);

	posix_spawn_file_actions_addclose (&action, STDIN_FILENO);
	posix_spawn_file_actions_addclose (&action, STDOUT_FILENO);
	posix_spawn_file_actions_addclose (&action, STDERR_FILENO);

	pid_t pid;
	const char *args[] = {"launchctl", "list", S_SSHDID, NULL};
	int status;

	status = posix_spawn(&pid, pp_launchctl, &action, NULL, (char* const*)args, NULL);
	if (status == 0) {
		if (waitpid(pid, &status, 0) != -1) {
			// command OK
			if ( WIFEXITED(status) != 0 ){
				status = WEXITSTATUS(status);
			} else {
				bhLog("check ERROR: WIFEXITED(status) = 0");
				status = 1;
			}

		} else {
			bhLog("check ERROR: waitpid() = -1");
			status = -11;
		}
	} else {
		bhLog("check ERROR: posix_spawn(,%s,,,,) = %d - %s", pp_launchctl, status, strerror(status));
		status = -12;
	}
	posix_spawn_file_actions_destroy(&action);

	if ( status < 0 )
		return status;
	if ( status > 0 )
		return 0;

	return 1;
} // static int check_status() {

// main list idea from https://stackoverflow.com/questions/49506579/how-to-find-the-pid-of-any-process-in-mac-osx-c
// a compact doc on what sysctl() returns with KERN_PROCARGS2 is in
// https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/print.c
static void
kickem() {

	size_t amaxs;
	int amax, mib[3], argn, cnt=1000;
	char *args = NULL, *chars;

	// how many procs max? It was 1000 in iOS11, it's 2000 in iOS14 & 15
	amaxs = sizeof(cnt);
	if ( sysctlbyname("kern.maxproc", &cnt, &amaxs, NULL, 0) == -1 ){
		cnt = 2000;
	}

	// see if we can run the sysctl procedures for finding proc args
	amaxs = sizeof(amax);
	if ( sysctlbyname("kern.argmax", &amax, &amaxs, NULL, 0) != -1 ){
		args = (char *)malloc(amax);
		if (args != NULL) { // well now it needs to get freed
			amaxs = (size_t)amax;
			mib[0] = CTL_KERN;
			mib[1] = KERN_PROCARGS2;
		}
	}

	pid_t pids[cnt];
	int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
	int n_proc = bytes / sizeof(pids[0]);
	for (int pi = 0; pi < n_proc; pi++) {
		struct proc_bsdinfo proc;
		int st = proc_pidinfo(pids[pi], PROC_PIDTBSDINFO, 0, &proc, PROC_PIDTBSDINFO_SIZE);
		if (st == PROC_PIDTBSDINFO_SIZE) {
			if ( strncmp(proc.pbi_name, "sftp-server", 11)==0 ){
				kill(pids[pi], SIGTERM); // yeah those clients usually try to immediately reconnect
			} else if ( strncmp(proc.pbi_name, "scp", 3)==0 ){
				// need to find the scp processes with the -t or -f arg, else they are clients outward

				if ( args != NULL ){
					mib[2] = pids[pi];
					if (sysctl(mib, 3, args, &amaxs, NULL, 0) != -1) {
						memcpy(&argn, args, sizeof(argn)); // argn is now the argc for the process
						chars = args + sizeof(argn); // exec_path & args start after the argc
						cnt = 0; // for marking where it starts
						while ( chars < &args[amaxs] && chars < &args[amaxs] ){
							if ( *chars == '\0' ){
								cnt++;
							} else if ( cnt>0 && *chars != '\0' ){
								// now here the proc name should start (the path name)
								break;
							}
							chars += 1;
						}
						if ( chars < &args[amaxs] ){ // else if we got to the end it must be empty
							for (cnt=0; cnt < argn && chars < &args[amaxs]; chars++) {
								if (*chars == '\0') { // this is how they're separated there. so we also go past the 1st, the proc name.
									cnt++;
									if ( cnt < argn ){
										if ( strncmp(chars+1,"-t",2)==0 || strncmp(chars+1,"-f",2)==0 ){
											kill(pids[pi], SIGTERM);
											break;
										}
									} else
										break; // no need to go further
								}
							}
						}
					}
				}
			}
		}
	}
	if (args != NULL) {
		free(args);
	}

	// 1st idea actually came from
    // https://stackoverflow.com/questions/25628316/osx-yosemite-getutxent-returning-the-same-user-twice
    setutxent();
    while(1) {
    	struct utmpx *user_info = getutxent();
		if ( user_info == NULL ){
			break;
		} else if ( user_info->ut_type == USER_PROCESS && strlen(user_info->ut_host) > 0 ){
			kill(user_info->ut_pid, SIGHUP);
		}
    }
    endutxent();

} // static void kickem() {

// oo = 0|1 (= off|on)
// return 0:ok, >10:Error
static int
switch_onoff(_Bool oo) {

	// if bootastoggled, (un)load -w
	// if runonboot, load -w(ok), unload(ok if was loaded)
	// if notonboot, load -F(ok), unload -w(ok if was loaded)
	const char * sw = "-w";
	int8_t prefget;
	if ( (prefget = prefs_get("b",0)) < 0 )
		return -prefget;
	if ( prefget == 0 ){
		if ( (prefget = prefs_get("n",0)) < 0 )
			return -prefget;
		if ( prefget == 1 ){
			sw = oo==1 ? "-F" : "-w";
		} else {
			sw = oo==1 ? "-w" : "-F";
		}
	}

	posix_spawn_file_actions_t action;
	posix_spawn_file_actions_init(&action);
	posix_spawn_file_actions_addclose (&action, STDIN_FILENO);
	posix_spawn_file_actions_addclose (&action, STDOUT_FILENO);
	posix_spawn_file_actions_addclose (&action, STDERR_FILENO);

	pid_t pid;
	const char *args[] = {"launchctl", oo==0?"unload":"load", sw, fp_opensshdp, NULL};
	int status;
	status = posix_spawn(&pid, pp_launchctl, &action, NULL, (char* const*)args, NULL);
	if (status == 0) {
		if (waitpid(pid, &status, 0) != -1) {
			status = 0; // don't need to know this. If unloaded and wasn't running, it prolly return 113. If the plist isn't there it still returns 0.
		} else {
			bhLog("switch(%d) ERROR: waitpid = -1", oo);
			status = 13;
		}
	} else {
		bhLog("switch(%d) ERROR: posix_spawn(,%s,,,,) = %d - %s", oo, pp_launchctl, status, strerror(status));
		status = 14;
	}
	posix_spawn_file_actions_destroy(&action);

	if ( status==0 ){
		char msg[strlen(S_SSHDID)+5] = S_SSHDID; // I hope the compiler makes that strlen quite static
		strcat(msg, oo==0 ? "/off" : "/on");
		CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFStringCreateWithCString(NULL,msg,kCFStringEncodingASCII), NULL, NULL, true);
	}

	// anything given as arg overrides the kickEm/letEmLinger setting
	if ( g_forcekick == 2 || // if ordered, do it no matter which way it got switched
		( oo == 0 && g_forcekick != 1 && // while turning off, kickEm unless forbidden to
			prefs_get( "k", 1 )==1
		)
	) kickem();

	return status;

} // int switch_onoff(int oo) {

#pragma mark /etc/ssh/sshd_config ie. fp_opensshdc

// determine which keywords (in AuthenticationMethods) a sequence has.
// *am_content should not point to a space! (it would remain like that and this here would do nothing)
// Return int -2="unknown", -1="unknown mfa", 0="any", 1=pwd, 2=pubkey, 3=mfa
// when done the parameter *am_content points to the next space or the line break (or the end).
static int8_t
read_aume_list(char ** am_content){

	int8_t ret = 0;
	uint8_t cnt = 0;
	size_t clen = strlen(*am_content);
	char* space = strpbrk(*am_content," "); // this is where the *am_content should be when we're done
	if ( space == NULL ) space = *am_content +clen;
	char* comma = NULL;

	do {
		if ( cnt>0 && strncmp(*am_content,",",1)==0 ) *am_content += 1; // happens after the 1st iteration

		cnt += 1;
		comma = strpbrk(*am_content,",");
		if ( comma != NULL && comma > space ){
			comma = NULL;
		}

		if ( strncmp(*am_content,s_ap,strlen(s_ap))==0 ){ // "password"
			if ( cnt>1 ){
				if ( ret>=2 ) ret = 3;
			} else {
				ret = 1;
			}
			*am_content += strlen(s_ap);
		} else if ( strncmp(*am_content,s_ak,strlen(s_ak))==0 ){ // "publickey"
			if ( cnt>1 ){
				if ( ret==1 ) ret = 3;
			} else {
				ret = 2;
			}
			*am_content += strlen(s_ak);
		} else if ( strncmp(*am_content,s_ai,strlen(s_ai))==0 ){ // "keyboard-interactive"
			if ( cnt>1 ){
				if ( ret>=2 ) ret = 3;
			} else {
				ret = 1;
			}
			*am_content += strlen(s_ai);
		} else {
			if ( cnt>1 || comma != NULL )
				ret = -1;
			else if ( strncmp(*am_content,"any",3) != 0 )
				ret = -2;
			comma = NULL; // "any" cannot co-exist with others so no need to go further. With anything unknown we also bail.
		}
	} while ( comma != NULL );

	*am_content = space;
	return ret;
} // static int8_t read_aume_list(char ** am_content){

static _Bool
write_ports_config(FILE * fp, uint16_t *nports, int8_t cnt){
	for ( int8_t i=0; i<cnt; i++ ){
		if ( fprintf(fp, "%s%d\n", s_pt, nports[i]) < 0 )
			return 0;
	}
	return 1;
}

// The keyword to write is given as the 2nd arg, yes/no as the 3rd arg
static _Bool
write_yesno(FILE * fp, const char *kw, _Bool yesno){
	if ( fprintf(fp, "%s%s\n", kw, yesno==1?s_ys:s_no) < 0 )
		return 0;
	return 1;
}

// Write AuthenticationMethods line, based on our new_authmethd.
// If it's >=0 then we do write it.
// Return 1 or 0 - whether it succeeded.
static _Bool
write_aume(FILE * fp, int8_t am){

//any:0 AuthenticationMethods password publickey keyboard-interactive
//pwd:1 AuthenticationMethods password keyboard-interactive
//key:2 AuthenticationMethods publickey
//mfa:3 AuthenticationMethods publickey,password publickey,keyboard-interactive

	if ( am >= 0 ){
		if ( fprintf(fp, "%s%s%s%s%s%s%s%s\n",
			s_ta, // "AuthenticationMethods "
			am>1 ? s_ak : "", // "publickey"
			am==3 ? "," : "",
			(am==2) ? "" : s_ap, // "password"
			(am==2) ? "" : " ",
			(am==0||am==3) ? s_ak : "", // "publickey"
			am==3 ? "," : (am==0 ? " " : ""),
			am==2 ? "" : s_ai // "keyboard-interactive"
			) <0 ) return 0;
	}
	return 1;

}

static _Bool
write_listener(FILE * fp, _Bool global){
	if ( fprintf(fp, "%s%s%s\n", global==1 ? "#" : "", s_la, global==1 ? "0.0.0.0" : "127.0.0.1") <0 ) return 0;
	if ( fprintf(fp, "%s%s::%s\n", global==1 ? "#" : "", s_la, global==1 ? "" : "1") <0 ) return 0;
	return 1;
}



#pragma mark /Library/LaunchDaemons/com.openssh.sshd.plist ie. fp_opensshdp

static void
open_plist(){
	if ( ff_opensshdp == NULL )
		ff_opensshdp = fopen(fp_opensshdp,"r");
	else
		rewind(ff_opensshdp);
}

// Strip any leading xml comments from the line. Actually just make the pointer point to the end of the comment.
// If the comment doesn't end in this given string/line then advance ff_opensshdp to the end of the line where it does
//   and have the string pointer point to where it ends there.
// If `anywhere' != 0 then seach anywhere not just the beginning.
// If `anywhere' > 1 then don't include the bytes of *istr in the return calculation (meaning the caller has already processed this one).
//	 it might return <1 if the comment also ended inside that string. But if it didn't end here, we proceed like described above.
// Return the total length of the discarded portion (possibly minus the initial string length), <1 if nothing found.
// (this is not a full-blown xml parser, eg. we don't check if the "<!--" could be inside CDATA or even if it's inside a node value which would be a plist error, or an attribute, etc.)
static long
plist_comment( char ** istr, int8_t anywhere ){
	if ( *istr==NULL )
		return 0;

	long len = 0;
	int llen = 0;
	char * comme = NULL;
	char * istrtc = ltrim_ws(*istr); // left trimmed

	if ( anywhere > 0 ){
		istrtc = strstr(*istr,"<!--");
		if ( istrtc==NULL )
			return 0; // len
		if ( anywhere > 1 )
			len -= strlen(*istr);
	}

	if ( strncmp(istrtc,"<!--",4)==0 ){

		if ( anywhere != 1 )
			len += (istrtc - *istr);
		*istr = istrtc;
		*istr += 4; // remember Psychic Paper :)
		len += 4;

		do {

			if ( (comme = strstr(*istr,"-->")) != NULL ){
				llen = strlen(*istr) - strlen(comme) + 3;
				len += llen;
				*istr += llen;

				if ( strlen(*istr) > 3 )
					len += plist_comment(istr, 0);
				return len;
			}
			len += strlen(*istr);
		} while ( fgets(*istr,128,ff_opensshdp) != NULL );
	}
	return len;
} // static long plist_comment( char ** istr, int8_t anywhere ){

// Populate nports and return the amount populated, set `outside' to reflect if it's 0=localhost only, 1=not localhost only.
// Return a negative if cannot read the file (error).
// One-line xml or such stuff isn't really supported. This is only a parser for a very secific plist.
static int8_t
plist_ports(uint16_t *nports, size_t max_ports, _Bool *outside){
	open_plist();
	if ( ff_opensshdp == NULL )
		return -1;

	if ( max_ports > INT8_MAX ) max_ports = INT8_MAX;
	int8_t pcnt = 0;
	_Bool nonlocal = 0; // if we find even one that isn't localhost or the SockNodeName missing, or no ports at all, we make it 1 meaning an outside listener (it could be some specific address but still it isn't localhost).

	char istra[128];
	char * istr; // a pointer separately so we can pass it around and have it target different parts in the char arr etc.
	char * istrtc; // left trimmed

	char * str_str = NULL; // "<string>" (strlen==8)
	_Bool str_int = 0; // if it's "<integer>" (strlen==9), _Bool is good enough
	int8_t sock_xml_level = -1;
	uint8_t sock_key = 0; // 1=SockServiceName, 2=SockNodeName
	int prt = 0;
	_Bool has_nodena = 0;
	long llen = 0; //// TODO?: only for istrtc len so uint8_t should be sufficient

	while ( fgets(istra,128,ff_opensshdp) != NULL ){
		istr = istra;

		plist_comment( &istr, 0 );

		istrtc = ltrim_ws(istr);
		llen = strlen(istrtc);
		if ( llen < 6 ) continue; // the shortest thing we'd care about is "<dict>"	or like "<a><!--"

		if ( sock_xml_level >= 0 ){
			if ( strncmp(istrtc,"<dict>",6)==0 ){
				sock_xml_level++; // 2, sock_xml_level>0

				if ( sock_xml_level > 1 )
					has_nodena = 0;

				if ( llen > 9 ) // strlen("<dict><!--") == 10
					istrtc += 6;
				else
					continue;
			}
		} else if ( strncmp(istrtc,"<key>Sockets</key>",18)==0 ){ // 1, sock_xml_level==0, passthru
			sock_xml_level = 0;

			if ( llen > 21 ) // strlen("<key>Sockets</key><!--") == 22
				istrtc += 18;
			else
				continue;
		}

		if ( sock_xml_level > 0 ){

			if ( sock_key==1 ){
				sock_key = 0; // only care about the 1st line, else it would be a plist format error anyway
				str_int = 0;

				if ( strncmp(istrtc,"<string>",8)==0 ){
					str_str = strstr(istr,"<string>");
				} else if ( strncmp(istrtc,"<integer>",9)==0 ){
					str_str = strstr(istr,"<integer>");
					str_int = 1;
				} else {
					continue; // launchctl might start up the /service/ but it isn't really listening
				}

				prt = strtol(str_str + 8 + str_int, NULL, 10);
				if ( prt <= 0 || prt>65535 ){
					if ( str_int==0 && strncmp(str_str,"<string>ssh</string>",20)==0 ){
						prt = 22;
					}
				}

				if ( (str_str = strstr(istrtc, str_int==0 ? "</string>" : "</integer>")) != NULL ){ //strlen("</string><!--") == 13
					istrtc = str_str;
					istrtc += 9+str_int;
				} // else plist error ie. break ??

			} else if ( sock_key==2 ){
				sock_key = 0; // only care about the 1st line, else it would be a plist format error anyway
				if ( strncmp(istrtc,"<string>",8) != 0 ){
					continue; // launchd just won't listen on this port although it starts up the /service/
				}

				if ( nonlocal == 0 && strncmp(istrtc,"<string>127.0.0.1</string>",26) !=0 && strncmp(istrtc,"<string>::1</string>",20) !=0 )
					nonlocal = 1;

				if ( (str_str = strstr(istrtc,"</string>")) != NULL ){ //strlen("</string><!--") == 13
					istrtc = str_str;
					istrtc += 9;
				} // else plist error ie. break ??

			} else {
				if ( sock_xml_level > 1 ){
					if ( strncmp(istrtc,"<key>SockServiceName</key>",26)==0  ){ // several are allowed wtf?, the last one wins
						sock_key = 1;
						prt = 0;
						if ( llen > 29 ) // strlen("<key>SockServiceName</key><!--") == 30
							istrtc += 26;
						else
							continue;
					} else if ( strncmp(istrtc,"<key>SockNodeName</key>",23)==0 ){ // several are allowed wtf?, the last one wins
						sock_key = 2;
						has_nodena = 1;
						if ( llen > 26 ) // strlen("<key>SockNodeName</key><!--") == 27
							istrtc += 23;
						else
							continue;
					}
				} // if ( sock_xml_level > 1 ){
				if ( sock_key==0 ){
					// could possibly avoid this if ( strlen(istrtc) < llen ), probably not worth it
					if ( strncmp(istrtc,"</dict>",7)==0 ){ // 3

						sock_xml_level--;
						if ( sock_xml_level == 1 ){ // a socket dict done, see what we got (the last key wins)
							if ( nonlocal == 0 && has_nodena == 0 )
								nonlocal = 1;
							if ( prt>0 && prt<=65535 ){
								nports[pcnt] = (uint16_t)prt;
								if ( pcnt>0 && in_array(nports[pcnt], nports, pcnt) == 1 )
									nports[pcnt] = 0;
								else {
									pcnt++;

									if ( pcnt >= max_ports )
										break;
								}
							}
						}
						if ( sock_xml_level < 1 ){ // 4, passthru
							break;
						}

						if ( llen > 10 ) // strlen("</dict><!--") == 11
							istrtc += 7;
						else
							continue;

					} // if ( strncmp(istrtc,"</dict>",7)==0 ){
				} // if ( sock_key==0 ){
			} // if ( sock_key==1 ){ ... } else if ( sock_key==2 ){ ... } else {
		} // if ( sock_xml_level > 0 ){


		if ( plist_comment( &istrtc, (llen < strlen(istrtc) ? 0 : 1) ) > 0 ){
			llen = strlen(istrtc);
			if ( llen > 6 ){ // could be searching for "<dict>" (+ a newline)
				fseek(ff_opensshdp, 0-llen, SEEK_CUR);
			}
		}

	} // while ( fgets(istra,128,ff_opensshdp) != NULL ){

	if ( pcnt > 0 )
		*outside = nonlocal;

	return pcnt;

} // static int8_t plist_ports(uint16_t *nports, size_t max_ports, _Bool *outside){

// Determine if it's launchd based OpenSSH, set the global g_isindsshd.
//  return 1 or 0 - whether it has the Sockets key
//  return a negative if cannot read the file
// This should be run early, so to possibly detect if it isn't an xml plist and leave it alone.
//// TODO?: could be vice versa ie. 0=yes so if cast to _Bool then only 0 would be saying yes
static int8_t
plist_has_sockets(){
	if ( g_isindsshd > 0 ){
		return g_isindsshd==1 ? 0 : 1;
	}

	open_plist();
	if ( ff_opensshdp == NULL )
		return -1;

	char istra[128];
	char * istr; // a pointer separately so we can pass it around and have it target different parts in the char arr etc.
	char * istrtc; // left trimmed

	while ( fgets(istra,128,ff_opensshdp) != NULL ){

		istr = istra;
		plist_comment( &istr, 0 );
		istrtc = ltrim_ws(istr);

		if ( strncmp(istrtc,"<key>Sockets</key>",18)==0 ){
			g_isindsshd = 2;
			return 1;
		} else {
			plist_comment( &istrtc, 1 );
		}

	}

	g_isindsshd = 1;
	return 0;
} // static int8_t plist_has_sockets(){

// ret 1=ok, should carry on from where it was left by plist_comment()
// ret 0=error? reading was bad so nothing written but ff_opensshdp is where it was left by plist_comment(), handles are still open.
// ret -1=error, handles closed, content got written ok but ff_opensshdp was at an unknown position.
// ret -2=error, handles closed, content didn't get read good so nothing written. ff_opensshdp was at an unknown position.
// ret -3=error, handles closed, nothing got written but ff_opensshdp was at an unknown position.
// ret -4=error, handles closed, content didn't get written good. ff_opensshdp was at the beginning of the comment.
static int8_t
plist_copy_comment( FILE * ofs, long minuspos, long clen ){

	long lend_pos = ftell(ff_opensshdp);
	long csta_pos = lend_pos - minuspos - clen;

	char cbuf[clen];

	if ( fseek(ff_opensshdp, csta_pos, SEEK_SET) != 0 ){ // to the beginning of the comm
		/*why would this happen, then what do we do...?*/
		// Houston, we dunno where we are
		return finish_cleanup(-3, ofs, NULL, NULL);
	}
	size_t cbuf_s = fread(cbuf, 1, clen, ff_opensshdp); // read the comm
	if ( cbuf_s == clen ){ // check
		if ( fwrite(cbuf, 1, cbuf_s, ofs) != clen ){ // write it
			// Houston? what got written?
			return finish_cleanup(-4, ofs, NULL, NULL);
		}
	} // else { /*why would this happen, then what do we do...? well we're not writing a portion of the comm, better just forget it */ }
	if ( fseek(ff_opensshdp, lend_pos, SEEK_SET) == 0 ){ // back to where we were ie. end of this line
		if ( cbuf_s != clen ){ // nothing got written
			// but we're now at the correct position
			return 0;
		}
		// DONE
		return 1;
	}

	/* why would this happen, then what do we do...? */
	// Houston, we're somewhere we're not supposed to be, maybe.

	return finish_cleanup( cbuf_s==clen ? -1 : -2 , ofs, NULL, NULL);

} // static int8_t plist_copy_comment( FILE * ofs, long minuspos, long clen ){

// we know that iOS 11 & 12 can have either type, iOS 13 can in principle also have sshd, but not for a regular user (Procurs.us 1st one ver "8.2" had it)
// return 0 - if it succeeded, either all well done or didn't need to do anything
// return 16 if ff_opensshdp cannot be read, 41-44 if it cannot be written
static uint8_t
write_ports_plist( uint16_t *nports, int8_t cnt, _Bool outside ){

	if ( g_isindsshd==0 && plist_has_sockets() < 0 )
		return 16;
	if ( g_isindsshd==1 )
		return 0;

	open_plist();

	if ( ff_opensshdp != NULL ){

		char plist_file_tmp[strlen(fp_opensshdp)+5];
		strcpy(plist_file_tmp, fp_opensshdp);
		strcat(plist_file_tmp, ".tmp");
		touchremove(0,plist_file_tmp);
		FILE * ofs;
		ofs = fopen(plist_file_tmp,"w");

		if ( ofs != NULL ){

			// <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
			// 111+1+1
			char istra[128];
			char * istr; // a pointer separately so we can pass it around and have it target different parts in the char arr etc.
			char * istrtc; // left trimmed
			long llen = 0; //// TODO?: only for istrtc len so uint8_t should be sufficient
			long clen = 0;
			int8_t sock_xml_level = -1, sock_written = 0, cc = 0;

			// (Elucubratus build of OpenSSH 8.3-1 started making the plist with tabs instead of spaces)
			char ind[5] = { 0,0,0,0,0 };

			while ( fgets(istra,128,ff_opensshdp) != NULL ){

				istr = istra;

/**
Only 3 strings are of interest
"<key>Sockets</key>"
"<dict>"
"</dict>"
And the dict stuff only if we've seen the Sockets (don't care about anything before that, it goes as is).
The dict ones finally cancel out and then we don't care again.
Between the <dict> and </dict>, comments yeah ok let's copy those, but nothing beside those.
We write our own content before any of the comments, after the "<dict>" line.
**/

				clen = plist_comment( &istr, 0 );
				if ( clen > 0 ){
					// comments get preserved

					cc = plist_copy_comment( ofs, strlen(istr), clen );
					if ( cc < 0 ){ // ok didn't write the comment, never mind // handles are open if it isn't negative
						// 44 if writing bad
						// 16 if reading bad
						return finish_cleanup( cc==-4 ? 44 : 16, ofs, plist_file_tmp, NULL ); // ERROR out
					}

					if ( sock_xml_level > 0 && strpbrk(istr,"<")==NULL ){
						// not going to write this line, but now we found some comment and we wrote it, it probably needs an EOL
						if ( fputs("\n", ofs) == EOF ){
							return finish_cleanup( 44, ofs, plist_file_tmp, NULL ); // ERROR out
						}
					}

				} // if ( clen > 0 ){

				istrtc = ltrim_ws(istr);
				llen = strlen(istrtc);

				if ( ind[0] == 0 && istrtc > istr ){
					if ( istr[0] == ' ' )
						strncpy(ind, "    ", (istrtc-istr>4) ? 4 : strspn(istr, " ") );
					else
						ind[0] = '\t';
				}

				if ( sock_xml_level >= 0 ){
					if ( strncmp(istrtc,"</dict>",7)==0 ){ // 3
						sock_xml_level--;
						if ( sock_xml_level < 1 )
							sock_xml_level = -1;
						istrtc += 7;
					} else if ( strncmp(istrtc,"<dict>",6)==0 ){
						sock_xml_level++; // 2, sock_xml_level>0
						istrtc += 6;
					}
				} else if ( strncmp(istrtc,"<key>Sockets</key>",18)==0 ){ // 1, sock_xml_level==0, passthru
					sock_xml_level = 0;
					istrtc += 18;
				}

				if ( sock_xml_level < 1 ){ // not "our section"
					if ( fputs(istr, ofs) == EOF ){
						return finish_cleanup( 44, ofs, plist_file_tmp, NULL ); // ERROR out
					}
				} else {

					if ( sock_written < 1 ){ // 1st time only

						if ( fprintf(ofs, "%s<dict>\n", ind) <0 ){
							return finish_cleanup( 44, ofs, plist_file_tmp, NULL ); // ERROR out
						}

						char lv6[70] = {0};
						if ( outside==0 ){
							sprintf(lv6, "%s%s%s<key>SockNodeName</key>\n%s%s%s<string>::1</string>\n", ind, ind, ind, ind, ind, ind);
						}

						char sock_nr[3] = {0};
						char cport[6];
						for (int8_t pi = 0; pi<cnt; pi++){
							sock_written++;

							if ( sock_written > 1 ) snprintf(sock_nr, 3, "%d", sock_written);
							if ( nports[pi] == 22 ) snprintf(cport, 4, "ssh");
							else snprintf(cport, 6, "%d", nports[pi]);

							if ( fprintf(ofs, "%s%s<key>SSH%sListener%s</key>\n%s%s<dict>\n%s%s%s%s<key>SockServiceName</key>\n%s%s%s<string>%s</string>\n%s%s</dict>\n",
								// SSHListener
								ind, ind, // 2
								outside ? "" : "v6", // 3
								sock_nr, // 4
								// dict
								ind, ind, // 6
								// SockNodeName
								lv6, // 7
								// SockServiceName
								ind, ind, ind, // 10
								ind, ind, ind, // 13
								cport, // 14
								// /dict
								ind, ind ) // 16
							<0 ) return finish_cleanup( 44, ofs, plist_file_tmp, NULL ); // ERROR out

							// localhost IPv4
							if ( outside==0 &&
							fprintf(ofs, "%s%s<key>SSHv4Listener%s</key>\n%s%s<dict>\n%s%s%s<key>SockNodeName</key>\n%s%s%s<string>127.0.0.1</string>\n%s%s%s<key>SockServiceName</key>\n%s%s%s<string>%s</string>\n%s%s</dict>\n",
								// SSHListener
								ind, ind, // 2
								sock_nr, // 3
								// dict
								ind, ind, // 5
								// SockNodeName
								ind, ind, ind, // 8
								ind, ind, ind, // 11
								// SockServiceName
								ind, ind, ind, // 14
								ind, ind, ind, // 17
								cport, // 18
								// /dict
								ind, ind ) // 20
							<0 ) return finish_cleanup( 44, ofs, plist_file_tmp, NULL ); // ERROR out

						} // for (int8_t pi = 0; pi<cnt; pi++){
						if ( sock_written == 0 )
							sock_written = 1; // we're done, even if there were no ports. This should be taken care of by the calling code though.

					} // if ( sock_written == 0 ){
				} // if ( sock_xml_level < 1 ){ ... } else {

				clen = plist_comment( &istrtc, sock_xml_level > 0 ? 1 : 2 );
				if ( clen > 0 ){
					llen = strlen(istrtc);

					cc = plist_copy_comment( ofs, llen, clen );
					if ( cc < 0 ){ // handles are open if it's below 2
						return finish_cleanup( cc==-4 ? 44 : 16, ofs, plist_file_tmp, NULL ); // ERROR out
					}

					if ( sock_xml_level > 0 && strpbrk(istrtc,"<")==NULL ){
						// we didn't write the full line, but now we found some comment and we wrote it, it probably needs an EOL
						if ( fputs("\n", ofs) == EOF ){
							return finish_cleanup( 44, ofs, plist_file_tmp, NULL ); // ERROR out
						}
					} else {
						// now need to see if there's anything relevant after the comment (if it was multiline). so fseek back to what was given by plist_comment().
						fseek(ff_opensshdp, 0-llen, SEEK_CUR);
					}
				} // if ( clen > 0 ){
			} // while ( fgets(istr,128,ff_opensshdp) != NULL ){
			fclose(ofs);
			fclose(ff_opensshdp); // closing it before any renaming et al

			char plist_file_b[strlen(fp_opensshdp)+2];
			strcpy(plist_file_b,fp_opensshdp);
			strcat(plist_file_b,".b");

			int ren = rename(fp_opensshdp, plist_file_b);
			if ( ren == 0 ){
				// overwrite
				ren = rename(plist_file_tmp, fp_opensshdp);
				if ( ren == 0 ){
					touchremove(0,plist_file_b);
					return 0; // total success
				}
				// revert from backup
				rename(plist_file_b, fp_opensshdp);
				//// TODO: check if the rename succeeded ?? well, if rename to .b succeeded, I assume this will as well (yeahyeah, never ass u me!).
				return 43; // error renaming tmp to final
			}
			touchremove(0,plist_file_tmp);
			return 42; // error renaming to backup

		} // if ( ofs != NULL ){
		else {
			fclose( ff_opensshdp );
			return 41; // error opening for writing
		}
	} // if ( ff_opensshdp != NULL ){
	return 16;

} // static uint8_t write_ports_plist( uint16_t *nports, int8_t cnt, _Bool outside ){

#pragma mark sessions info stuff

// input: pid, output char* adr which should be reserved like `char adr[INET6_ADDRSTRLEN]'
// return whether it succeeded
static _Bool
foreign_ip_of_pid(pid_t pid, char* adr){
	_Bool ret = 0;

	int nbs = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
	struct proc_fdinfo *proc_fd_info = (struct proc_fdinfo *)malloc(nbs);
	if (proc_fd_info == NULL)
		return ret;
	int n_proc_fds = nbs / PROC_PIDLISTFD_SIZE;
	proc_pidinfo(pid, PROC_PIDLISTFDS, 0, proc_fd_info, nbs);
	for(int e = 0; e < n_proc_fds; e++) {
		if(proc_fd_info[e].proc_fdtype == PROX_FDTYPE_SOCKET) {
			struct socket_fdinfo socket_info;
			proc_pidfdinfo(pid, proc_fd_info[e].proc_fd, PROC_PIDFDSOCKETINFO, &socket_info, PROC_PIDFDSOCKETINFO_SIZE);
			if(socket_info.psi.soi_kind == SOCKINFO_TCP){

				if (socket_info.psi.soi_family == AF_INET){
					if ( inet_ntop(socket_info.psi.soi_family,
							&socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4,
							adr, INET_ADDRSTRLEN) != NULL )
							ret = 1;
					break;

				} else if (socket_info.psi.soi_family == AF_INET6){
					if ( inet_ntop(socket_info.psi.soi_family,
							&socket_info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6,
							adr, INET6_ADDRSTRLEN) != NULL )
							ret = 1;
					break;
				}
			}
		}
	}
	free(proc_fd_info);
	return ret;
} // static _Bool foreign_ip_of_pid(pid_t pid, char* adr)[

// input pid, output uid,procname,tvsec. procname should prolly be initialized NULL as we don't know what's in there
// return whether it succeeded. 0=error, 1=success, 2=success but uid is below 0
static uint8_t
uid_from_pid(pid_t pid, uid_t* uid, char** procname, long* tvsec){
	uint8_t ret = 0;

    struct kinfo_proc process;
    size_t proc_buf_s = sizeof(process);

    // Compose search path for sysctl.
    const u_int path_len = 4;
    int path[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};

    int sysctlResult = sysctl(path, path_len, &process, &proc_buf_s, NULL, 0);

    // If sysctl did not fail and process with PID available - take UID.
    if ((sysctlResult == 0) && (proc_buf_s != 0))
    {
        *uid = process.kp_eproc.e_ucred.cr_uid;
        *procname = strdup(process.kp_proc.p_comm); // must be free()'d
        *tvsec = process.kp_proc.p_starttime.tv_sec;
		ret = uid>=0 ? 1 : 2;
    }

    return ret;
} // _Bool uid_from_pid(pid_t pid, uid_t uid, char* procname, long tvsec){

// input: ppid, output: pid,uid,procname,tvsec,username.
// procname should prolly be initialized NULL as we don't know what's in there
// username should prolly be initialized at least char username[23] as starting iOS 12 there's `_reportmemoryexception' user
// return 0=error, 1=ok(with a strdup'd username and procname), 2=ok(without a strdup'd username, but still a strdup'd procname)
static uint8_t
childinfo(pid_t ppid, pid_t* pid, uid_t* uid, char** procname, long* tvsec, char** username){
	uint8_t ret = 0;

	int b = proc_listchildpids(ppid, NULL, 0); // this seems to work, unlike proc_listallpids().
	pid_t *cids = (pid_t *)malloc(sizeof(pid_t)*b);
	int d = proc_listchildpids(ppid, cids, b);

	// if <0 then either master, or we're at the millisecond when a child hasn't been spawn yet
	// if >1 then it should be the master (in iOS anyways)

	// let's only see about the 1st (and only?) child
	if ( d == 1 ){
		uint8_t ufp = uid_from_pid(cids[0], uid, procname, tvsec);
		if ( ufp == 1 ){
			if ( strcmp(S_SSHD, *procname) != 0 ){
				struct passwd *pwd;
				*pid = cids[0];

				// https://stackoverflow.com/questions/1610203/unix-programming-not-sure-how-to-use-the-passwd-struct
				struct passwd pw;
				char buf[1024];
				if (getpwuid_r(*uid, &pw, buf, sizeof buf, &pwd)==0){
					*username = strdup(pw.pw_name);
					ret = 1;
				} else {
					*username = "unknown";
					ret = 2;
				}
			} // so else it means child is sshd, which means this main pid is the master sshd listener
			else free(procname); // strdup'd ie. malloc'd in uid_from_pid()
		} else if ( ufp==2 )
			free(procname); // strdup'd ie. malloc'd in uid_from_pid()
	}

	free(cids);
	return ret;
} // static _Bool childinfo(pid_t ppid, pid_t* pid, uid_t* uid, char** procname, long* tvsec, char** username){

// https://stackoverflow.com/questions/49506579/how-to-find-the-pid-of-any-process-in-mac-osx-c
// return whether there aren't any users logged in. Basically _Bool but ok to exit the program with (0 means someone is in).
static int
sshd_procs( _Bool json ){
	pid_t pids[2048];
	int a = proc_listallpids(pids, 2048*sizeof(int));

	uint8_t ok_parent = 0;
	uint8_t ok_child = 0;
	_Bool ok_ip = 0;
	pid_t pid = 0;
	uid_t uid = -1;
	long tvsec = 0;
	char* procname = NULL;
	char* username = NULL;
	char adr[INET6_ADDRSTRLEN];
	int userc = 0;

	if ( json == 1 )
		printf("[");

	for (int i = 0; i < a; i++) {
		if ( pids[i] < 2 ) continue; // never mind about kernel_task and launchd

		ok_parent = uid_from_pid(pids[i], &uid, &procname, &tvsec); // only checking the procname here. will overwrite all with childinfo()
		if ( ok_parent != 1 || strcmp(S_SSHD, procname) != 0 ){
			if ( ok_parent > 0 ) free(procname); // strdup'd ie. malloc'd in uid_from_pid()
			continue;
		}
		if ( ok_parent > 0 ) free(procname); // strdup'd ie. malloc'd in uid_from_pid()

		ok_child = childinfo(pids[i], &pid, &uid, &procname, &tvsec, &username);
		if ( ok_child == 0 || pid < 2 ){ // error OR either OS main procs like kernel or launchd
			if ( ok_child > 0 ) free(procname); // strdup'd ie. malloc'd in uid_from_pid()
			if ( ok_child == 1 ) free(username); // strdup'd ie. malloc'd in childinfo()
			continue;
		}
		userc++;
		ok_ip = foreign_ip_of_pid(pids[i], adr);

		if ( json==1 ){
			if ( userc > 1 )
				printf(",");
			printf("{\"u\":%d,\"n\":\"%s\",\"i\":\"%s\",\"c\":\"%s\",\"p\":%d,\"r\":%d,\"s\":%ld}", uid, username, ok_ip==1?adr:"", procname, pid, pids[i], tvsec);
		} else {
			printf("------------\n");
			printf(" uid: %d\n", uid);
			printf("user: %s\n", username);
			printf("  ip: ");
			if ( ok_ip == 1 )
				printf("%s", adr);
			printf("\n cmd: %s\n", procname);
			printf(" pid: %d\n", pid);
			printf("ppid: %d\n", pids[i]);
			printf("since %s", ctime( (const time_t *) &tvsec ) ); // ctime() gives it with a linebreak.
		}
		if ( ok_child > 0 ) free(procname); // strdup'd ie. malloc'd in uid_from_pid()
		if ( ok_child == 1 ) free(username); // strdup'd ie. malloc'd in childinfo()

	} // for (int i = 0; i < a; i++) {

	if ( json == 1 )
		printf("]");

	return userc == 0 ? 1 : 0;

} // static int sshd_procs( _Bool json ){

#pragma mark help/doc

static void
short_help(char *argv[], _Bool as_err){
	if ( as_err==1 ){
		fprintf(stderr,"ERROR: unrecognized subcommand: %s\nSee `%s -h' (short) or `%s --help' (long)\n", argv[1], argv[0], argv[0]);
		return;
	}
	printf("%s Usage:\n", argv[0]);
	printf("%s on [ports a|a0 w|w0 u|u0 g|g0] - switch on\n", argv[0]);
	printf("%s of [ports a|a0 w|w0 u|u0 g|g0] - switch off\n", argv[0]);
	printf("%s s       - show on/off status\n", argv[0]);
	printf("%s p       - show port(s)\n", argv[0]);
	printf("%s a       - show if root allowed\n", argv[0]);
	printf("%s w       - show if pwd auth allowed\n", argv[0]);
	printf("%s u       - show if key auth allowed\n", argv[0]);
	printf("%s t       - show if key & pwd required\n", argv[0]);
	printf("%s g       - show if listening globally\n", argv[0]);
	printf("%s i[j]    - list active sessions\n", argv[0]);
	printf("%s l       - Let'Em Linger\n", argv[0]);
	printf("%s k       - Kick'Em\n", argv[0]);
	printf("%s e       - Even If Locked\n", argv[0]);
	printf("%s f       - Forbid If Locked\n", argv[0]);
	printf("%s r       - Run On Boot\n", argv[0]);
	printf("%s n       - Not On Boot\n", argv[0]);
	printf("%s b       - Boot As Toggled\n", argv[0]);
	printf("%s d       - show Default state\n", argv[0]);
	printf("%s v       - show the version\n", argv[0]);
	printf("%s -h      - this help\n", argv[0]);
	printf("%s h       - full help/description\n", argv[0]);
	printf("See `%s help' or `%s --help' for more info (landscape orientation recommended).\n", argv[0], argv[0]);
}
static void
long_help(char *argv[]){
	printf("%s                 without a subcommand, check the return status: 0=on, 1=off.\n", argv[0]);
	printf("%s on [22 ayes wyes uyes gyes]\n", argv[0]);
	printf("%s off [22 ayes wyes uyes gyes]\n", argv[0]);
	printf("     optional args after on/off (their order doesn't matter):\n");
	printf("          port number(s separated by commas) or `-'\n");
	printf("          a[1|yes|0|no|-] allow root login\n");
	printf("          w[1|yes|0|no|-] allow password auth\n");
	printf("          u[1|yes|0|no|-] allow auth by public key\n");
	printf("          g[1|yes|0|no|-] listen on all addresses\n");
	printf("%s status          print whether SSH is on or off.\n", argv[0]);
	printf("%s port            print the configured port(s)\n", argv[0]);
	printf("%s allowRoot       print whether root is allowed to log in\n", argv[0]);
	printf("%s withPassword    print whether it's allowed to login with a password\n", argv[0]);
	printf("%s usingKey        print whether it's allowed to login with a key\n", argv[0]);
	printf("%s twoFactor       print whether both pwd and key are required\n", argv[0]);
	printf("%s globalListener  print whether it isn't localhost only\n", argv[0]);
	printf("%s info | ij       list active sessions, return 1 if there aren't any\n", argv[0]);
	printf("%s letEmLinger     (setting) do not logout users when turning ssh server off\n", argv[0]);
	printf("%s kickEm          (setting) close all sessions when turning ssh server off\n", argv[0]);
	printf("%s evenIfLocked    (setting) allow toggling from CC while locked\n", argv[0]);
	printf("%s forbidIfLocked  (setting) forbid toggling from CC while locked\n", argv[0]);
	printf("%s runOnBoot       (setting) ssh server enabled when re-jailbroken\n", argv[0]);
	printf("%s notOnBoot       (setting) ssh server disabled when re-jailbroken\n", argv[0]);
	printf("%s bootAsToggled   (setting) when re-jailbroken, follow the last toggled state\n", argv[0]);
	printf("%s defaultState    print the startup state (bootAsToggled/runOnBoot/notOnBoot)\n", argv[0]);
	printf("%s version | -v    print the version of this tool\n", argv[0]);
	printf("%s -h              print short help\n", argv[0]);
	printf("%s help | --help   print this text\n\n", argv[0]);
	printf("This tool is used internally by the [OpenSSH Settings] (u.blanxd.opensshport)\n");
	printf(" and some OpenSSH server toggle tweaks.\n\n");
	printf("Any return >=10 is an error in any case. You should really always check it.\n\n");
	printf("Specifying port(s) after on/off is optional. If SSH is running, and you give a\n");
	printf(" different port or ports, then SSH gets restarted. Several ports (max 8) may be\n"); //// TODO: global max_ports or something
	printf(" specified, separated by commas. Not all ports are accepted, in such cases no\n");
	printf(" errors are reported, but those don't get applied. (22 or 1001 through 65535,\n");
	printf(" and a few high ports are also being avoided)\n\n");
	printf("Specifying whether to allow root login (a), passwrod auth (w), public key\n");
	printf(" auth (u), and whether to accept connections from the outside (g)\n");
	printf(" are optional. They get saved in any case if given. If it differs from the\n");
	printf(" running setting, then the ssh server may get restated (especially in case sshd\n");
	printf(" is listening by itself and not via launchd).\n");
	printf(" If both pwdAuth(w) and keyAuth(u) are given 0/no then this tool makes them\n");
	printf(" both `yes' and implements it `two factor' ie. both get to be Required.\n\n");
	printf("Printing sessions with ij gives json output (without a newline).\n\n");
	printf("let'em linger / kick'em is a u.blanxd.SSHswitch setting/func,\n");
	printf(" its default is Kick'em, ie. every incoming ssh/scp/sftp session gets\n");
	printf(" terminated when it turns the server off.\n");
	printf("evenIfLocked / forbidIfLocked is a toggle tweaks' setting,\n");
	printf(" its default is ForbidIfLocked, ie. no toggle works on a locked lockscreen.\n");
	printf("bootAsToggled / runOnBoot / notOnBoot is a u.blanxd.SSHswitch setting,\n");
	printf(" it defines how we call launchctl to start/stop the ssh server. When changed,\n");
	printf(" the ssh server may get restarted, or turned on briefly if it isn't running.\n\n");
	printf("Only the 1st unique chars matter,\n");
	printf(" info requests: s/p/a/w/u/t/g/i/d/v/-v/-h/h/--,\n");
	printf(" commands: on/of/l/k/e/f/r/n/b.\n\n");
	printf("Documentation: info and man pages (if the system supports either) and in\n");
	printf("(/var/jb)/var/mobile/Documents/SSHswitch-doc/ and Files.app.\n\n");
}

int main(int argc, char *argv[], char * envp[]) {

#pragma mark subcommand -h
	if ( argc > 1 && strncmp(argv[1],"-h",2)==0 ){
		short_help(argv, 0);
		return 0;
	}
#pragma mark subcommand help,--help
	if ( argc > 1 && ( argv[1][0] == 'h' || strncmp(argv[1],"--",2)==0 ) ){
		long_help(argv);
		return 0;
	}
#pragma mark subcommand version
	if ( argc > 1 && ( argv[1][0] == 'v' || strncmp(argv[1],"-v",2)==0 ) ){
		printf("%s\n", BUILD_VERSION); // this gets read from version.txt at compile time, see Makefile
		return 0;
	}

	setuid(0);
	/* really actually only for iOS11 Electra really */
	if ( getuid() != 0 ){
		electra_patch_setuid();
		setuid(0);
		if ( getuid() != 0 ){ // so Electra just maybe needs some random time, let's try a few times...
			setuid(0);
			if ( getuid() != 0 ){
				setuid(0);
			}
		}
	}
	/**/
	setgid(0);
	if ( getuid() != 0 ){
		return 10;
	}

	// From here on out, let's do any exit through finish_cleanup() (unless it's known to be an error of reading the fp_opensshdp)
	// It closes possible prefs file handle and plist handle, and other stuff via given params.

	// requests that don't require reading OpenSSH files nor running lanchctl, our own settings and such
	int8_t prefget;
	if ( argc > 1 ){
#pragma mark subcommand info,ij
		if ( argv[1][0] == 'i' ){
			return sshd_procs( strncmp(argv[1],"ij",2)==0 ? 1 : 0 );
		} else
#pragma mark subcommand evenIfLocked
		if ( argv[1][0] == 'e' ){
			return finish_cleanup( prefs_set("e") ,NULL,NULL,NULL);
		} else
#pragma mark subcommand forbidIfLocked
		if ( argv[1][0] == 'f' ){
			return finish_cleanup( prefs_set("f") ,NULL,NULL,NULL);
		} else
#pragma mark subcommand let 'em Linger
		if ( argv[1][0] == 'l' ){
			return finish_cleanup( prefs_set("l") ,NULL,NULL,NULL);
		} else
#pragma mark subcommand kick 'em
		if ( argv[1][0] == 'k' ){
			return finish_cleanup( prefs_set("k") ,NULL,NULL,NULL);
		} else
#pragma mark subcommand defaultState
		if ( argv[1][0] == 'd' ){
			prefget = prefs_get("b",0);
			if ( prefget<0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);

			if ( prefget<1 ){
				prefget = prefs_get("n",0);
				if ( prefget<0 )
					return finish_cleanup( -prefget ,NULL,NULL,NULL);
				printf("%s\n", prefget==1 ? "notOnBoot" : "runOnBoot");
			} else {
				printf("bootAsToggled\n");
			}
			return finish_cleanup( 0 ,NULL,NULL,NULL);
		}
	} // if ( argc > 1 ){

	int status = paths(); // status is the old on/off status, but for a moment here it denotes the success of paths()
	if ( !status ){
		bhLog("ERROR: determined %s but it isn't there", pp_launchctl);
		return 17;
	} else if ( status>1 ){
		// ok so not in /var/jb any more, need to use env JB_ROOT_PATH
		pp_launchctl = JB_ROOT_PATH(pp_launchctl);
		fp_opensshdp = JB_ROOT_PATH(fp_opensshdp);
		fp_opensshdc = JB_ROOT_PATH(fp_opensshdc);
	}

	status = check_status(); // 0:notRunning, 1:running, <0:Error
	if ( status < 0 ){
		return -status; // Error 11 or 12
	}

	if (argc < 2){
		return status==0 ? 1 : 0;
	}

	// From here on out, there must be an argv[1]

	// Status
#pragma mark subcommand status
	if ( argv[1][0] == 's' ) {
		printf("o%s\n", status>0 ? "n" : "ff");
		return 0;
	} else

	// launchctl settings
#pragma mark Startup setup
	if ( strchr("rnb",argv[1][0]) != NULL ){ // ?? can there be an argv[1] consisting of only a '\0'? (in which case this would always be true)
		int8_t prefset,
			ono = prefs_get("o",1); // could be -1 if no ssh setting has ever been changed with this tool

		if (
			( ono == 0 && argv[1][0] != 'n' ) // pref=off && switching to runOnBoot or bootAsToggled, need pref=on
			||
			( ono != 0 && argv[1][0] == 'n' ) // pref=on && switching to notOnBoot, need pref=off
			||
			( ono != 0 && argv[1][0] == 'b' && status == 0 ) // pref=on && switching to bootAsToggled && currently not running, need pref=off
		){
			// if this fails, it isn't critical (unless the prefs file gets f*d), the important thing to write is one of the next 3.
			if ( (prefset = prefs_set( ono!=0 ? "off" : "on" )) >=30 )
				return prefset;
		}

		g_forcekick = 1; // not kicking them off for this setting
		int swoo;

#pragma mark subcommand runOnBoot
		if ( argv[1][0] == 'r' ){

			if ( (prefget = prefs_get("r",1)) <0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);
			if ( prefget==1 ){
				// good already
				return finish_cleanup( 0 ,NULL,NULL,NULL);
			}

			// Need to get to `load -w' / `unload -F'.
			// - if not running and bootastog (was unload -w), need to load -w, unload -F
			// - if running and bootastog (was load -w), good
			// - if not running and notonboot (was unload -w), need to load -w, unload -F
			// - if running and notonboot (was load -F), need to unload -*, load -w

			if ( (prefget = prefs_get("n",1)) <0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);
			// now prefget==1 is notonboot, prefget==0 is bootastog

			if ( (prefset = prefs_set("r")) >0 )
				return finish_cleanup( prefset ,NULL,NULL,NULL);

			if ( prefget==0 && status != 0 ) // running, was bootastog
				return finish_cleanup( 0 ,NULL,NULL,NULL);
			// else go for the restart/restop

		} else // if ( argv[1][0] == 'r' ){
#pragma mark subcommand notOnBoot
		if ( argv[1][0] == 'n' ){

			if ( (prefget = prefs_get("n",1)) <0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);
			if ( prefget==1 ){
				// good already
				return finish_cleanup( 0 ,NULL,NULL,NULL);
			}

			// Need to get to `load -F' / `unload -w'.
			// - if not running and bootastog (was unload -w), good
			// - if running and bootastog (was load -w), need to unload -w, load -F
			// - if not running and runonboot (was unload -F), need to load -*, unload -w
			// - if running and runonboot (was load -w), need to unload -w, load -F

			if ( (prefget = prefs_get("b",1)) <0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);
			// now prefget==1 is bootastog, prefget==0 is runonboot

			if ( (prefset = prefs_set("n")) >0 )
				return finish_cleanup( prefset ,NULL,NULL,NULL);

			if ( prefget==1 && status==0 ) // not running, was bootastog
				return finish_cleanup( 0 ,NULL,NULL,NULL);
			// else go for the restart/restop

		} else // if ( argv[1][0] == 'n' ){
#pragma mark subcommand bootAsToggled
		if ( argv[1][0] == 'b' ){

			if ( (prefget = prefs_get("b",1)) <0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);
			if ( prefget==1 ){
				// good already
				return finish_cleanup( 0 ,NULL,NULL,NULL);
			}

			// Need to get to `load -w' / `unload -w'.
			// - if not running and notonboot (was unload -w), good
			// - if running and notonboot (was load -F), need to unload -*, load -w
			// - if not running and runonboot (was unload -F), need to load -*, unload -w
			// - if running and runonboot (was load -w), good

			if ( (prefget = prefs_get("n",1)) <0 )
				return finish_cleanup( -prefget ,NULL,NULL,NULL);
			// now prefget==1 is notonboot, prefget==0 is runonboot

			if ( (prefset = prefs_set("b")) >0 )
				return finish_cleanup( prefset ,NULL,NULL,NULL);

			if (
				( prefget==1 && status==0 ) // not running and notonboot
				||
				( prefget==0 && status!=0 ) // running and runonboot
			) return finish_cleanup( 0 ,NULL,NULL,NULL);
			// else go for the restart/restop

		} // if ( argv[1][0] == 'b' ){

		swoo = switch_onoff( status==0 ? 1 : 0 );
		if ( swoo > 0 )
			return finish_cleanup(swoo ,NULL,NULL,NULL);

		return finish_cleanup( switch_onoff( status==0 ? 0 : 1 ) ,NULL,NULL,NULL);

	} // if ( strchr("rnb",argv[1][0]) != NULL ){

	// From here on out, it must be something about OpenSSH settings themselves, or Kick'Em
	// we're left with
	/**
	set:
		on [port(s) a[0|no|1|yes|-] w[0|no|1|yes|-] u[0|no|1|yes|-] g[0|no|1|yes|-] k[0|no|1|yes|-] l[0|no|1|yes|-]]
		off [port(s) a[0|no|1|yes|-] w[0|no|1|yes|-] u[0|no|1|yes|-] g[0|no|1|yes|-] k[0|no|1|yes|-] l[0|no|1|yes|-]]
	get:
		port [awutglkefrnbv]
		allowRoot
		withPassword
		usingKey
		twoFactor
		globalListener
	**/

	uint8_t get_set = argv[1][0] == 'o' ? 1 : 0; // ==0:get something, >=1:set something
		// potentially 9 different options 0,1,2,4,8,16,32,64,128
		// 0: only read
		// 1: turn on/off (switching might be unnecessary but 1 remains until the end)
		// 2: set_port
		// 4: set_allowroot
		// 8: set_passwauth
		// 16: set_pubkeauth
		// 32: set_authmethd
		// 64: set_glistener
	uint8_t the_return = 0;
	_Bool onoff = ( (get_set & 1) && argv[1][1] == 'n' ) ? 1 : 0; // doesn't matter what it is unless get_set. Well also for reporting an unrecognized arg.

#pragma mark sshd_config & com.openssh.sshd.plist

	int old_port = 22;
	_Bool oldp_is_new = 1;
	_Bool get_port = ( get_set==0 && argv[1][0] == 'p' ) ? 1 : 0;

	uint16_t old_ports[30]; // just a number, not reporting nor even reading more than that. But could use INT8_MAX.
	int8_t c_old_ports = 0;
	uint8_t get_all = 0; // potentially 9 different options 0,1,2,4,8,16,32,64,128
	if ( get_port==1 ){

		if ( argc > 2 ){
			uint8_t get_pref = 0; // potentially 9 different options 0,1,2,4,8,16,32,64,128
			for (int argn=2; argn<argc; argn++){
				if ( strpbrk(argv[argn],"a") != NULL ) get_all |= 1;
				if ( strpbrk(argv[argn],"w") != NULL ) get_all |= 2;
				if ( strpbrk(argv[argn],"u") != NULL ) get_all |= 4;
				if ( strpbrk(argv[argn],"t") != NULL ) get_all |= 8;
				if ( strpbrk(argv[argn],"g") != NULL ) get_all |= 16;
				if ( strpbrk(argv[argn],"vefklrnb") != NULL ){ // tweak settings
					get_all |= 32;
					if ( strpbrk(argv[argn],"v") != NULL && !(get_pref & 1) ){ printf("v%s\n", BUILD_VERSION); get_pref |= 1; } // this gets read from version.txt at compile time, see Makefile
					if ( strpbrk(argv[argn],"e") != NULL && !(get_pref & 2) ){ printf("e%s\n", prefs_get("e",0)==1?s_ys:s_no ); get_pref |= 2; }
					if ( strpbrk(argv[argn],"f") != NULL && !(get_pref & 4) ){ printf("f%s\n", prefs_get("f",0)==1?s_ys:s_no ); get_pref |= 4; }
					if ( strpbrk(argv[argn],"k") != NULL && !(get_pref & 8) ){ printf("k%s\n", prefs_get("k",0)==1?s_ys:s_no ); get_pref |= 8; }
					if ( strpbrk(argv[argn],"l") != NULL && !(get_pref & 16) ){ printf("l%s\n", prefs_get("l",0)==1?s_ys:s_no ); get_pref |= 16; }
					if ( strpbrk(argv[argn],"r") != NULL && !(get_pref & 32) ){ printf("r%s\n", prefs_get("r",0)==1?s_ys:s_no ); get_pref |= 32; }
					if ( strpbrk(argv[argn],"n") != NULL && !(get_pref & 64) ){ printf("n%s\n", prefs_get("n",0)==1?s_ys:s_no ); get_pref |= 64; }
					if ( strpbrk(argv[argn],"b") != NULL && !(get_pref & 128) ){ printf("b%s\n", prefs_get("b",0)==1?s_ys:s_no ); get_pref |= 128; }
				}
			}
		} else if ( argv[1][1] == 'r' ){
			// SSHonCC v.1.2 (2018-07) - v.1.4 (2020-05) Settings component compatibility, shouldn't be necessary but who knows. Before v.1.2 it only allowed changing/reading the ports so this is covered anyway.
			get_all |= 1;
			get_all |= 2;
		}
	}

	_Bool new_glistener = 1; // default
	// default is no IPs defined (0.0.0.0 and :: commented) ie. global, but there could be many, so we can only call it non-localonly when the whole file gets read (config or plist).
	_Bool old_glistener = 0;
	_Bool get_glistener = ( get_set==0 && ( get_all & 16 || argv[1][0] == 'g' ) ) ? 1 : 0;

	// need to know whether sshd itself is listening (for a restart), if setting something. Or if possibly need to read the plist.
	if ( (get_set & 1) || get_port==1 || get_glistener==1 ){
		if ( plist_has_sockets() < 0 ) // plist_has_sockets() sets the global g_isindsshd to non-zero (unless it's negative itself ie. error)
			return finish_cleanup( 16 ,NULL,NULL,NULL); // error reading fp_opensshdp
		// so now g_isindsshd is set
	}
	// read ports and/or about the localhost restriction from plist, if appropriate.
	if ( g_isindsshd==2 &&
		( get_port==1 || get_glistener==1 || (get_set & 1) )
	){
		// maybe sort them? ... let the GUI do that actually.
		c_old_ports = plist_ports( old_ports, sizeof(old_ports)/sizeof(old_ports[0]), &old_glistener );
		if ( c_old_ports < 0 )
			return finish_cleanup( 16 ,NULL,NULL,NULL); // error reading fp_opensshdp

		if ( get_port==1 ){ // if set_port then need to compare them later
			for (int8_t i=0; i<c_old_ports; i++){
				printf("%d\n", old_ports[i] );
			}
		}
		if ( get_glistener==1 ){
			printf("%s%s\n", get_all>0?"g":"", old_glistener==1?s_ys:s_no );
		}
		if ( get_set==0 && (get_all==0 || get_all==16 || get_all==32 || get_all==48) ){
			return finish_cleanup( (get_all>0 && status==0) ? 1 : 0 ,NULL,NULL,NULL);
		}
	}

	_Bool get_allowroot = ( get_set==0 && ( (get_all & 1) || argv[1][0] == 'a' ) ) ? 1 : 0;
	_Bool get_passwauth = ( get_set==0 && ( (get_all & 2) || argv[1][0] == 'w' ) ) ? 1 : 0;
	_Bool get_pubkeauth = ( get_set==0 && ( (get_all & 4) || argv[1][0] == 'u' ) ) ? 1 : 0;
	_Bool get_authmethd = ( get_set==0 && ( (get_all & 8) || argv[1][0] == 't' ) ) ? 1 : 0;

	if (
		( !get_set && !get_port && !get_glistener && !get_allowroot && !get_passwauth && !get_pubkeauth && !get_authmethd )
		||
		( (get_set & 1) && !onoff && argv[1][1] != 'f' )
	){
		// bad args
		short_help(argv, 1);
		return finish_cleanup(15 ,NULL,NULL,NULL);
	}

	// v.1.1.0: non-positional on/off args, starting with the letter or numbers(&comma) only
	_Bool let_onoff = 0;
	char *let_port = NULL,
		*let_allowroot = NULL,
		*let_passwauth = NULL,
		*let_pubkeauth = NULL,
		*let_glistener = NULL,
		*let_forcekick = NULL;

	if ( (get_set & 1) && argc > 2 ){
		char * scnd;
		for (int argn=2; argn<argc; argn++){
			// the last one of each wins, don't care how many repeating ones there are.
			if ( strchr("pawugkl",argv[argn][0]) != NULL ){
				scnd = argv[argn] + 1;
				let_onoff = 1;

				switch(argv[argn][0]){
					case 'p': let_port = scnd; break;
					case 'a': let_allowroot = scnd; break;
					case 'w': let_passwauth = scnd; break;
					case 'u': let_pubkeauth = scnd; break;
					case 'g': let_glistener = scnd; break;
					case 'k': let_forcekick = scnd; break;
					case 'l': // the opposite of kick'em
						let_forcekick = arg_skip(scnd) // can skip with `l-'
										? NULL
										: ( arg_no(scnd)
											? "1"
											: "0" );
						break;
				}
			} else
			if ( argv[argn][1] != 0 && strspn(argv[argn],"1234567890,")==strlen(argv[argn]) ){
				let_port = argv[argn];
				if ( argn>2 ) let_onoff = 1;
			} else
			if ( let_onoff == 0 ){ // 1st args until something lettered appears
				// not lettered, meaning v.1.0.x style positional
				switch(argn){
					case 2: let_port = argv[argn]; break;
					case 3: let_allowroot = argv[argn]; break;
					case 4: let_passwauth = argv[argn]; break;
					case 5: let_pubkeauth = argv[argn]; break;
					case 6: let_forcekick = argv[argn]; break;
				}
			}
		} // for (int argn=2; argn<argc; argn++){
	} // if ( (get_set & 1) && argc > 2 ){

	uint16_t new_ports[8]; //// TODO: global max_ports or something
	int8_t c_new_ports = 0;

	_Bool new_allowroot = 1; // default is yes
	_Bool old_allowroot = 1; // default is yes

	_Bool old_passwauth = 1; // default is yes
	_Bool old_kbdintera = 1; // default is yes
	_Bool old_usepam = 0; // default is no

	_Bool old_pubkeauth = 1; // default is yes

	int8_t new_authmethd = -4; // -4=no change, 0="any"/missing, 1=password/keyboard-interactive, 2=publickey, 3=mfa(publickey,password/keyboard-interactive)
	int8_t old_authmethd = 127; // unrecognized=<0, 0=any/(or missing), 1=password/keyboard-interactive, 2=publickey, 3=mfa(publickey,password/keyboard-interactive), >3=not set

	if ( let_port != NULL && !arg_skip(let_port) ){ // can skip with `p-'
		c_new_ports = ports_split(let_port, new_ports, sizeof(new_ports)/sizeof(new_ports[0]), 0); //// TODO: global max_ports or something
		if ( c_new_ports > 0 )
			get_set |= 2;
	}

	get_set |= 4* ( let_allowroot != NULL && !arg_skip(let_allowroot) ); // can skip with `a-'
	get_set |= 8* ( let_passwauth != NULL && !arg_skip(let_passwauth) ); // can skip with `w-'
	get_set |= 16* ( let_pubkeauth != NULL && !arg_skip(let_pubkeauth) ); // can skip with `u-'
	get_set |= 32* ( (get_set & 8) || (get_set & 16) );
	get_set |= 64* ( let_glistener != NULL && !arg_skip(let_glistener) ); // can skip with `g-'

	if ( let_forcekick != NULL && !arg_skip(let_forcekick) ) // can skip with `k-'
		g_forcekick = arg_no(let_forcekick) ? 1 : 2;

	// if it isn't an info request, it might be just an on/off or a force kick, don't need to read/write anything for these
	if ( get_set != 1 ){

#pragma mark need to read or write something

		if ( access( fp_opensshdc, get_set==0 ? R_OK : R_OK|W_OK ) != 0 ){
			return finish_cleanup( get_set==0 ? 18 : 21 ,NULL,NULL,NULL);
		}

		if ( (get_set & 4) && arg_no(let_allowroot) ) new_allowroot = 0;

		if ( (get_set & 8) ){
			if ( arg_no(let_passwauth) ){
				// means new_authmethd will be either 2(pubkey) or 3(mfa)
				if ( !(get_set & 16) ) new_authmethd = -3; // depends on old_pubkeauth, 3 - old_pubkeauth
				else new_authmethd = 2; // may turn into 3
			} else {
				// means new_authmethd will be either 0(any) or 1(password/keyboard-interactive)
				if ( !(get_set & 16) ) new_authmethd = -1; // depends on old_pubkeauth
				else new_authmethd = 1; // may turn into 0
			}
		} // if ( (get_set & 8) ){

		if ( (get_set & 16) ){
			if ( arg_no(let_pubkeauth) ){
				// means new_authmethd will be either 1(password/keyboard-interactive) or 3(mfa)
				if ( !(get_set & 8) ) new_authmethd = -3; // depends on old_passwauth, 3 - (old_passwauth*2)
				else if ( new_authmethd == 2 ) new_authmethd = 3; // ie. set_passwauth && given "0"
				else new_authmethd = 1; // may have been set 1 above but Must Not remain -4 so let's make sure ie. prevent a lockout
			} else {
				// means new_authmethd will be either 0(any) or 2(pubkey).
				if ( !(get_set & 8) ) new_authmethd = -2; // depends on old_passwauth
				if ( new_authmethd == 1 ) new_authmethd = 0; // allow either
				else new_authmethd = 2;
			}
		} // if ( (get_set & 16) ){

		if ( (get_set & 64) && arg_no(let_glistener) ) new_glistener = 0;

#pragma mark params parsed

		FILE * ifs;
		ifs = fopen (fp_opensshdc,"r");

		// better note the Match line as a bookmark in the file, all our global stuff Must come before this
		//		and if we're doing `local only', could put some stuff after this with "Match Address 127.0.0.0/8,::1/128"
		long b_b_mtch = 0; // 0-indexed byte position in the new file (not line number)

		_Bool found_la = g_isindsshd==2 ? 1 : 0;

		if ( ifs != NULL ){

#pragma mark read sshd_config

			char istr[256], // ie. max 255 chunks (possibly including '\n')
				*istrtc; // left-trimmed
			_Bool hasEOL=1, hadEOL; // anything past the 255 is pass-thru, usually only care about the 1st 71 really

			// actual Bookmarks
			uint16_t l_allowroot = 0; // 1-indexed line number
			uint16_t l_allowpass = 0; // 1-indexed line number
			uint16_t l_allowpubk = 0; // 1-indexed line number
			uint16_t l_authmethd = 0; // 1-indexed line number
			uint16_t l_challresp = 0; // 1-indexed line number
			uint16_t l_kbdintera = 0; // 1-indexed line number
			uint16_t l_usepam = 0; // 1-indexed line number

			uint16_t l_cnt = 0; // 1-indexed

			// READ the file

			while ( fgets(istr,256,ifs) != NULL ){

				if ( hasEOL ) l_cnt++;
				hadEOL = hasEOL;
				hasEOL = strchr(istr,'\n') != NULL;
				if ( !hadEOL ) continue;

				istrtc = ltrim_ws(istr);

				if ( istrtc[0] == '\n' || istrtc[0] == '\0' || istrtc[0] == '#' )
					continue;

				if ( ( get_port==1 || (get_set & 1) ) && strncmp(istrtc, s_pt, strlen(s_pt)) == 0 ){

					if ( g_isindsshd != 2 ){

						old_port = strtol(istrtc+strlen(s_pt), NULL, 10);
						if ( old_port > 0 && old_port < UINT16_MAX &&
							( c_old_ports==0 || in_array( (uint16_t)old_port, old_ports, c_old_ports) == 0 )
							&& c_old_ports < INT8_MAX
						){ // sanity check, and uniqueness
							if ( get_port==1 ){
								printf("%d\n", old_port );
							} else if ( c_old_ports < sizeof(old_ports)/sizeof(old_ports[0]) ) {
								old_ports[c_old_ports] = (uint16_t)old_port;
								if ( (get_set & 2) && oldp_is_new==1 ){
									// whether it exists in new_ports
									oldp_is_new = ( in_array( old_ports[c_old_ports], new_ports, c_new_ports) == 1 ) ? 1 : 0 ;
								}
							}
							c_old_ports++;
						}
					}

				} else
				if ( ( get_glistener==1 || (get_set & 1) ) &&
					strncmp(istrtc, s_la, strlen(s_la)) == 0  // "ListenAddress "
				){
					if ( g_isindsshd != 2 ){ // only if not launchd or unknown
						found_la = 1;
						// iOS/macOS by default only considers 127.0.0.1/32 not the full /8 as localhost
						if ( strncmp(istrtc+strlen(s_la),"127.0.0.1\n",10) != 0 && strncmp(istrtc+strlen(s_la),"::1\n",4) != 0 ){
							old_glistener = 1; // for this program, it isn't really meaning global but rather "not localhost only"
						}
					}
				} else
				if (
					l_allowroot == 0 &&
					( get_allowroot==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_pr,strlen(s_pr)) == 0 // "PermitRootLogin "
				){
					old_allowroot = strstr(istrtc," no") != NULL ? 0 : 1;
					l_allowroot = l_cnt;
					if ( get_allowroot==1 ){
						printf("%s%s\n", get_all>0?"a":"", old_allowroot==1?s_ys:s_no );
						if ( get_all==0 ){ // if only ar was requested
							break;
						}
					}

					if ( (get_set & 4) && new_allowroot==old_allowroot ){
						get_set ^= 4;
					}
				} else if (
					l_allowpass == 0 &&
					( get_passwauth==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_pa,strlen(s_pa)) == 0 // "PasswordAuthentication "
				){
					old_passwauth = strstr(istrtc," no") != NULL ? 0 : 1;
					l_allowpass = l_cnt;
				} else if (
					l_challresp == 0 && l_kbdintera == 0 && // only the 1st one matters
					( get_passwauth==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_ca,strlen(s_ca)) == 0 // "ChallengeResponseAuthentication "
				){
					// if `UsePAM yes' this might mean pwd auth is allowed
					// unless it's "no" or there's "AuthenticationMethods "
					// without "password" or "keyboard-interactive".
					old_kbdintera = strstr(istrtc," no") != NULL ? 0 : 1;
					l_challresp = l_cnt;
					// if both this and KbdInteractiveAuthentication exist, we'll comment this and use the other
				} else if (
					l_challresp == 0 && l_kbdintera == 0 && // only the 1st one matters
					( get_passwauth==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_ki,strlen(s_ki)) == 0 // "KbdInteractiveAuthentication "
				){
					// if `UsePAM yes' this might mean pwd auth is allowed
					// unless it's "no" or there's "AuthenticationMethods "
					// without "password" or "keyboard-interactive".
					old_kbdintera = strstr(istrtc," no") != NULL ? 0 : 1;
					l_kbdintera = l_cnt;
					// if both this and ChallengeResponseAuthentication exist, we'll comment that and use this
				} else if (
					l_usepam == 0 &&
					( get_passwauth==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_up,strlen(s_up)) == 0 // "UsePAM "
				){
					old_usepam = strstr(istrtc," yes") != NULL ? 1 : 0;
					l_usepam = l_cnt;
				} else if (
					l_allowpubk == 0 &&
					( get_pubkeauth==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_ka,strlen(s_ka)) == 0 // "PubkeyAuthentication "
				){
					old_pubkeauth = strstr(istrtc," no") != NULL ? 0 : 1;
					l_allowpubk = l_cnt;
				} else if (
					l_authmethd == 0 &&
					( get_authmethd==1 || (get_set & 1) ) &&
					strncmp(istrtc,s_ta,strlen(s_ta)) == 0 // "AuthenticationMethods "
					){
					// "any", "password", "publickey", "keyboard-interactive", "gssapi-with-mic", "hostbased", "none"

					char * am_content = istrtc+strlen(s_ta); // strlen("AuthenticationMethods ")
					int8_t am_seq = 0;

					do {
						am_content = ltrim_ws(am_content); // important! without this we'd make a read_aume_list() endless loop
						if ( am_content[0] == '\n' ) break;

						// Return int8_t -2="unknown", -1="unknown mfa", 0="any", 1=pwd, 2=pubkey, 3=mfa
						am_seq = read_aume_list( &am_content );

						// the bigger the better security but worse priority while reading it here. 1 and 2 are of equal priority though.
						if ( (old_authmethd==2 && am_seq==1) || (old_authmethd==1 && am_seq==2) )
							old_authmethd = 0;
						else if ( am_seq < old_authmethd ){
							old_authmethd = am_seq;
						}

					} while ( strpbrk(am_content," ") != NULL );

					l_authmethd = l_cnt;

				} // AuthenticationMethods

			} // while ( fgets(istr,256,ifs) != NULL ){

#pragma mark done reading sshd_config

			if ( old_authmethd > 3 ) old_authmethd = 0; // so it wasn't set in sshd_config

			if ( get_allowroot==1 && l_allowroot==0 ){ // need to report the default
				printf("%s%s\n", get_all>0?"a":"", s_ys );
			}

			// need to report this considering all combinations
			if ( get_passwauth==1 ){
				printf("%s%s\n",
					get_all>0?"w":"",
					(
						(
							old_passwauth==1 ||
							(old_usepam==1 && old_kbdintera==1)
						) && (
							old_authmethd >= 0 && old_authmethd != 2 // -1(unknown mfa) may also mean it's allowed but never mind for now
						)
					)
						? s_ys
						: s_no
				);
			}

			// need to report this considering all combinations
			if ( get_pubkeauth==1 ){
				printf("%s%s\n",
					get_all>0?"u":"",
					(old_pubkeauth==1
						&& old_authmethd >= 0 && old_authmethd != 1 ) // -1(unknown mfa) may also mean it's allowed but never mind for now
						? s_ys
						: s_no
					);
			}

			if ( get_authmethd==1 ){
				printf("%s%s\n",
					get_all>0?"t":"",
					( old_authmethd==3 )
						? s_ys
						: s_no
					);
			}

			if ( found_la==0 ) // not launchd listener and nothing in config
				old_glistener = 1;

			if ( get_glistener==1 && g_isindsshd != 2 )
				printf("%s%s\n", get_all>0?"g":"", old_glistener==1?s_ys:s_no );

			// old_ports are needed if anything gets written (ie. our prefs also get written)
			if ( c_old_ports == 0 && ( (get_set & 1) || get_port==1 ) ){
				if ( get_port==1 ){
					printf("22\n"); // so this must be `#Port 22'
				}
				old_ports[0] = 22;
				c_old_ports = 1;
			}
			// the above Port output should be the last output actually, wrap it up.
			if ( get_set==0 ){
				return finish_cleanup( (get_all>0 && status==0) ? 1 : 0 ,NULL,NULL, ifs );
			}
#pragma mark end of GET, remains possible SET

			if ( (get_set & 64) && new_glistener==old_glistener )
				get_set ^= 64;

			// compare new_ports to old_ports if it wasn't done while parsing sshd_config
			if ( (get_set & 2) && g_isindsshd == 2 ) {
				for (int8_t i=0; i<c_old_ports; i++){
					if ( in_array( old_ports[i], new_ports, c_new_ports) == 0 ){
						oldp_is_new = 0;
						break;
					}
				}
				// if oldp_is_new==1 still then new_ports contains something that old_ports doesn't
			}

			if ( (get_set & 2) && oldp_is_new==1 ){
				// if Port wasn't found in conf
				if ( c_old_ports == 0 ){
					old_ports[0] = 22;
					c_old_ports++; // =1
				}
				get_set ^= 2;
				for (int8_t i=0; i<c_new_ports; i++){
					if ( in_array(new_ports[i], old_ports, c_old_ports)==0 ){
						// old_ports contains something that new_ports doesn't
						get_set |= 2;
						break;
					}
				}
			} // if ( (get_set & 2) && oldp_is_new==1 ){

			if ( (get_set & 32) ) {
				if ( new_authmethd == -3 ){ // only one requested
					if ( (get_set & 16) )
						new_authmethd = 3 - (old_passwauth*2); // 3 or 1
					else
						new_authmethd = 3 - old_pubkeauth; // 3 or 2
				} else if ( new_authmethd == -2 )
					new_authmethd = 2 - (old_passwauth*2); // 2 or 0
				else if ( new_authmethd == -1 )
					new_authmethd = 1 - old_pubkeauth; // 1 or 0
				else if ( new_authmethd == -4 ) // this cannot happen but
					get_set ^= 32; // guard against any logic flaws somewhere above

				// now new_authmethd is definitely positive (cannot be -4 when we get here if set_authmethd)

				// decide if PasswordAuthentication/KbdInteractiveAuthentication needs to be written
				if ( old_usepam==1 ){
					if ( new_authmethd==2 ){ // don't allow pwd
						if ( old_passwauth==1 || old_kbdintera==1 ) get_set |= 8; // need to disable all of them
						else get_set ^= 8; // none were allowed, good
					} else { // allow pwd
						// we need all of the 3 keywords to be unset/commented so they're allowed as by default
						if ( old_passwauth==0 || old_kbdintera==0 )
							get_set |= 8; // need to enable at least one of them. We enable both pwd and kbd really.
					}
				} else {
					// keyboard-interactive doesn't play a role anyway without PAM (I guess)
					if ( (old_passwauth==0 && new_authmethd==2) || (old_passwauth==1 && new_authmethd!=2) ) get_set ^= 8;
					else get_set |= 8;
				}

				// decide if PubkeyAuthentication needs to be written
				if ( (old_pubkeauth==0 && new_authmethd==1) || (old_pubkeauth==1 && new_authmethd!=1) ) get_set ^= 16;
				else get_set |= 16;

				// decide if AuthenticationMethods needs to be written
				if ( new_authmethd == old_authmethd ) // if old was something negative ie. unknown then we definitely overwrite
					get_set ^= 32;

			} // if ( (get_set & 32) ) {

			// things may have been changed to /don't/ although we're in (get_set & 1) mode, if the request is what's already active
			if ( get_set > 1 ){

#pragma mark write sshd_config
				// WRITE the file

				rewind(ifs);

				char conf_file_tmp[strlen(fp_opensshdc)+5];
				strcpy(conf_file_tmp, fp_opensshdc);
				strcat(conf_file_tmp, ".tmp");

				FILE * ofs;
				ofs = fopen (conf_file_tmp,"w+"); // may need to rewind and play with it

				if ( ofs != NULL ){

					_Bool found_prt = 0;
					found_la = 0;
					l_allowroot = 0;
					l_allowpass = 0;
					// l_challresp remains denoting which one it was
					l_kbdintera = 0;
					l_allowpubk = 0;
					l_authmethd = 0;
					hasEOL=1;

					l_cnt = 0; // 1-indexed
					while ( fgets(istr,256,ifs) != NULL ){

						if ( hasEOL ) l_cnt++;
						hadEOL = hasEOL;
						hasEOL = strchr(istr,'\n') != NULL;

						istrtc = ltrim(istr," \t#");

						// Let's try to find the particular lines where the default commented stuff, or such, are.
						// And not inside some free text comments.
						// Not entirely possible I guess, without multi-pass, but let's try.

						if ( !hadEOL // continuing a long line
							|| b_b_mtch > 0 // if we have found that then we possibly rewind to above that later and mangle a bit more
							){
							if ( fputs(istr, ofs) <0 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						} else
						if ( (get_set & 2) &&
								strncmp(istrtc,s_pt,strlen(s_pt))==0 // "Port "
							){
							if ( found_prt==0 ){
								found_prt = 1;
								if ( write_ports_config(ofs,new_ports,c_new_ports) <1 )
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else
						if ( (get_set & 64) &&
								strncmp(istrtc,s_la,strlen(s_la))==0 // "ListenAddress "
							) {
							if ( found_la==0 ){
								found_la = 1;
								if ( write_listener(ofs, new_glistener) <1 )
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else
						if ( (get_set & 4) &&
								strncmp(istrtc,s_pr,strlen(s_pr)) == 0 && // "PermitRootLogin "
								( strncmp(istrtc+strlen(s_pr),s_ys,3) == 0 || strncmp(istrtc+strlen(s_pr),s_no,2) == 0 )
							){
							if ( l_allowroot==0 ){
								l_allowroot = 1;
								if ( write_yesno(ofs, s_pr, new_allowroot) <1 )
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else
						if ( (get_set & 8) &&
								strncmp(istrtc,s_pa,strlen(s_pa)) == 0 && // "PasswordAuthentication "
								( strncmp(istrtc+strlen(s_pa),s_ys,3) == 0 || strncmp(istrtc+strlen(s_pa),s_no,2) == 0 )
							){
							if ( l_allowpass==0 ){
								l_allowpass = 1;
								if ( write_yesno(ofs, s_pa, new_authmethd==2 ? 0 : 1) <1 )
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else
						if ( (get_set & 8) &&
								(
									( strncmp(istrtc,s_ki,strlen(s_ki)) == 0 &&  // "KbdInteractiveAuthentication "
										( strncmp(istrtc+strlen(s_ki),s_ys,3) == 0 || strncmp(istrtc+strlen(s_ki),s_no,2) == 0 ) )
									|| ( strncmp(istrtc,s_ca,strlen(s_ca)) == 0 && // "ChallengeResponseAuthentication "
										( strncmp(istrtc+strlen(s_ca),s_ys,3) == 0 || strncmp(istrtc+strlen(s_ca),s_no,2) == 0 ) )
								)
							){
							if ( l_kbdintera==0 ){
								l_kbdintera = 1;
								if ( write_yesno(ofs, l_challresp>0 ? s_ca : s_ki, new_authmethd==2 ? 0 : 1) <1 )
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else
						if ( (get_set & 16) &&
								strncmp(istrtc,s_ka,strlen(s_ka)) == 0 && // "PubkeyAuthentication "
								( strncmp(istrtc+strlen(s_ka),s_ys,3) == 0 || strncmp(istrtc+strlen(s_ka),s_no,2) == 0 )
							){
							if ( l_allowpubk==0 ){
								l_allowpubk = 1;
								if ( write_yesno(ofs, s_ka, new_authmethd==1 ? 0 : 1) <1 )
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else
						if ( (get_set & 32) &&
								strncmp(istrtc,s_ta,strlen(s_ta)) == 0 // "AuthenticationMethods "
							){
							if ( l_authmethd==0 ){
								l_authmethd = 1;
								if ( write_aume(ofs, new_authmethd) <1 ) // to write or not to write it? if it isn't really needed...
									return finish_cleanup(19,ofs,conf_file_tmp,ifs);
							}
						} else {
							// find where the Match line begins or if there's the default comment of the Match line
							if (
								strstr(istr,"# Example of overriding") != NULL
								|| strstr(istrtc,"Match") != NULL
							) b_b_mtch = ftell(ofs);

							if ( fputs(istr, ofs) <0 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);

						}

					} // while ( fgets(istr,256,ifs) != NULL ){
					fclose(ifs);

					// everything not yet written is dependent on where/if the "Match" line is. If there is none and the user has an Include somewhere with some additional conf, this is out of our scope.
					if (
						( (get_set & 2) && found_prt==0 )
						||
						( (get_set & 4) && l_allowroot==0 )
						||
						( (get_set & 8) && (l_allowpass==0 || l_kbdintera==0) )
						||
						( (get_set & 16) && l_allowpubk==0 )
						||
						( (get_set & 32) && l_authmethd==0 )
					){

						long ofs_end_pos = ftell(ofs);
						_Bool do_append = 0;

						// ie. get buffer of everything after 'Match', write our stuff, then append that buffer
						char ofs_end_buf[ b_b_mtch > 0 ? ofs_end_pos-b_b_mtch : 0 ];
						size_t ofs_end_buf_s = 0;
						if ( b_b_mtch > 0 ){
							if ( fseek(ofs, b_b_mtch, SEEK_SET) == 0 ){ // goto
								ofs_end_buf_s = fread(ofs_end_buf, 1, ofs_end_pos-b_b_mtch, ofs); // read buffer
								if ( ofs_end_buf_s == ofs_end_pos-b_b_mtch ){ // check
									if ( fseek(ofs, b_b_mtch, SEEK_SET) == 0 ) // goto
										do_append = 1;
								}
							}
						}

						if ( (get_set & 2) && found_prt==0 ){
							if ( write_ports_config(ofs,new_ports,c_new_ports) <1 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						}
						if ( (get_set & 4) && l_allowroot==0 ){
							if ( write_yesno(ofs, s_pr, new_allowroot) <1 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						}
						if ( (get_set & 8) && l_allowpass==0 ){
							if ( write_yesno(ofs, s_pa, new_authmethd==2 ? 0 : 1) <1 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						}
						if ( (get_set & 8) && l_kbdintera==0 ){
							if ( write_yesno(ofs, s_ki, new_authmethd==2 ? 0 : 1) <1 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);

						}
						if ( (get_set & 16) && l_allowpubk==0 ){
							if ( write_yesno(ofs, s_ka, new_authmethd==1 ? 0 : 1) <1 )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						}
						if ( (get_set & 32) && l_authmethd==0 ){
							if ( write_aume(ofs, new_authmethd) <1 ) // to write or not to write it? if it isn't really needed...
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						}

						if ( do_append==1 ){
							if ( fwrite(ofs_end_buf, 1, ofs_end_buf_s, ofs) != ofs_end_buf_s )
								return finish_cleanup(19,ofs,conf_file_tmp,ifs);
						}
					}

					fclose(ofs);

					// bckp
					char conf_file_b[strlen(fp_opensshdc)+3];
					strcpy(conf_file_b, fp_opensshdc);
					strcat(conf_file_b, ".b");

					int ren;
					ren = rename(fp_opensshdc, conf_file_b);
					if ( ren == 0 ){
						// overwrite
						ren = rename(conf_file_tmp, fp_opensshdc);
						if ( ren == 0 ){ // final total success
							touchremove(0,conf_file_b);
						} else {
							// revert from backup
							rename(conf_file_b, fp_opensshdc);
							//// TODO: check if the rename succeeded ??
							return finish_cleanup( 21 ,NULL,NULL,NULL );
						}
					} else {
						return finish_cleanup( 20 ,NULL,conf_file_tmp,NULL );
					}

				} // if ( ofs != NULL ){
				else{
					return finish_cleanup( 19 ,NULL,NULL, ifs );
				}

			} else { // if ( get_set > 1 ){
				// may get here if the on/off request mirrors what's already active
				fclose(ifs);
			}

		} // if ( ifs != NULL ){

		//// TODO?: a slight inconsistency, this might get written even if sshd_config didn't. Better this way but still...
		if ( (get_set & 2) || (get_set & 64) ){
			the_return += write_ports_plist(
				(get_set & 2) ? new_ports : old_ports,
				(get_set & 2) ? c_new_ports : c_old_ports,
				(get_set & 64) ? new_glistener : old_glistener
				);
		}

		// write our prefs
		if ( get_set>0 ){

#pragma mark write our prefs

			if ( prefs_oo_compose(
					prefs_get("n",1) ? 0 : ( prefs_get("r",1) ? 1 : onoff ),
					(get_set & 2) ? new_ports : old_ports,
					(get_set & 2) ? c_new_ports : c_old_ports,
					(get_set & 4) ? new_allowroot : old_allowroot,
					(get_set & 32)
						? new_authmethd
						: ( old_authmethd>3 // error reading sshd_config (should have really exited already, never getting here)
							? 0
							: old_authmethd
							),
					(get_set & 64) ? new_glistener : old_glistener
				)==0 // _Bool
			){
				if ( the_return==0 )
					the_return = 40;
			} else {
				int8_t setpref = prefs_set( g_pref_oo );
				if ( the_return==0 )
					the_return = setpref;
			}

		}

	} // if ( get_set != 1 ){

	if ( get_set==0 ){
		return finish_cleanup( (get_all>0 && status==0) ? 1 : 0 ,NULL,NULL,NULL );
	} else {

#pragma mark start/stop sshd or com.openssh.sshd

		// 1st, do a simple switchOn if that was requested.
		//	If an Off was requested, or we need a restart, do a switchOff.
		// 2nd, do a switchOn if a restart was needed.
		// status= 0:notRunning, 1:running

		_Bool restart =
			(get_set & 2) ||
			(get_set & 64) ||
			( g_isindsshd<2 && (
				(get_set & 4) || (get_set & 8) || (get_set & 16) || (get_set & 32)
			) )
				? 1
				: 0;

		if ( onoff != status || (onoff && restart) ){
			// simple on/off in bootAsToggled mode needs an update to prefs
			if ( get_set==1 && prefs_get("b",1) ) prefs_set( onoff ? "on" : "off" );

			// need to not kick 'em if it's onoff==1 and we're changing ports (unless deliberately specified)
			if ( g_forcekick==0 && onoff==1 && ((get_set & 2) || (get_set & 64)) )
				g_forcekick = 1;

			int swoo = switch_onoff( restart==1 || onoff==0 ? 0 : 1 );
			if ( swoo > 10 ){
				return finish_cleanup(swoo,NULL,NULL,NULL); // Error
			}

			if ( onoff==1 && restart==1 ){ // restart
				swoo = switch_onoff( 1 );
				if ( swoo > 10 ){
					return finish_cleanup(swoo,NULL,NULL,NULL); // Error
				}
			}
		} else if ( g_forcekick==2 )
			kickem();

	} // if ( get_set==0 ){ ... } else {

	return finish_cleanup( the_return,NULL,NULL,NULL );

} // main

// Blanxd.H @2018: if I don't have BBEdit at hand I use emacs (nox) if at all possible, and tabs.
// Local Variables:
// mode: C
// tab-width: 4
// c-basic-offset: 4
// indent-tabs-mode: t
// End:

// vim:ft=c

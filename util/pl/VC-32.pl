#!/usr/local/bin/perl
# VC-32.pl - unified script for Microsoft Visual C++, covering Win32,
# Win64 [follow $FLAVOR variable to trace the differences].
#

$ssl=	"ssleay32";
$crypto="libeay32";

$o='\\';
$cp='$(PERL) util/copy.pl';
$mkdir='$(PERL) util/mkdir-p.pl';
$rm='del /Q';

$zlib_lib="zlib1.lib";

# Santize -L options for ms link
$l_flags =~ s/-L("\[^"]+")/\/libpath:$1/g;
$l_flags =~ s/-L(\S+)/\/libpath:$1/g;

my $ff = "";

# C compiler stuff
$cc='cl';
if ($FLAVOR =~ /WIN64/)
    {
    # Note that we currently don't have /WX on Win64! There is a lot of
    # warnings, but only of two types:
    #
    # C4344: conversion from '__int64' to 'int/long', possible loss of data
    # C4267: conversion from 'size_t' to 'int/long', possible loss of data
    #
    # Amount of latter type is minimized by aliasing strlen to function of
    # own desing and limiting its return value to 2GB-1 (see e_os.h). As
    # per 0.9.8 release remaining warnings were explicitly examined and
    # considered safe to ignore.
    # 
    $base_cflags= " $mf_cflag";
    my $f = $shlib || $fips ?' /MD':' /MT';
    $lib_cflag='/Zl' if (!$shlib);	# remove /DEFAULTLIBs from static lib
    $opt_cflags=$f.' /Ox';
    $dbg_cflags=$f.'d /Od -DDEBUG -D_DEBUG';
    $lflags="/nologo /subsystem:console /opt:ref";

    *::perlasm_compile_target = sub {
	my ($target,$source,$bname)=@_;
	my $ret;

	$bname =~ s/(.*)\.[^\.]$/$1/;
	$ret=<<___;
\$(TMP_D)$o$bname.asm: $source
	set ASM=\$(ASM)
	\$(PERL) $source \$\@

$target: \$(TMP_D)$o$bname.asm
	\$(ASM) $afile\$\@ \$(TMP_D)$o$bname.asm

___
	}
    }
else	# Win32
    {
    $base_cflags= " $mf_cflag";
    my $f = $shlib || $fips ?' /MD':' /MT';
    $lib_cflag='/Zl' if (!$shlib);	# remove /DEFAULTLIBs from static lib
    $ff = "/fixed";
    $opt_cflags=$f.' /Ox /O2 /Ob2';
    $dbg_cflags=$f.'d /Od -DDEBUG -D_DEBUG';
    $lflags="/nologo /subsystem:console /opt:ref";
    }
$mlflags='';

$out_def ="out32";	$out_def.="dll"			if ($shlib);
			$out_def.='_$(TARGETCPU)'	if ($FLAVOR =~ /CE/);
$tmp_def ="tmp32";	$tmp_def.="dll"			if ($shlib);
			$tmp_def.='_$(TARGETCPU)'	if ($FLAVOR =~ /CE/);
$inc_def="inc32";

if ($debug)
	{
	$cflags=$dbg_cflags.$base_cflags;
	}
else
	{
	$cflags=$opt_cflags.$base_cflags;
	}

# generate symbols.pdb unconditionally
$app_cflag.=" /Zi /Fd\$(TMP_D)/app";
$lib_cflag.=" /Zi /Fd\$(TMP_D)/lib";
$lflags.=" /debug";

$obj='.obj';
$asm_suffix='.asm';
$ofile="/Fo";

# EXE linking stuff
$link="link";
$rsc="rc";
$efile="/out:";
$exep='.exe';
if ($no_sock)		{ $ex_libs=''; }
elsif ($FLAVOR =~ /CE/)	{ $ex_libs='winsock.lib'; }
else			{ $ex_libs='ws2_32.lib'; }

if ($FLAVOR =~ /CE/)
	{
	$ex_libs.=' $(WCECOMPAT)/lib/wcecompatex.lib'	if (defined($ENV{'WCECOMPAT'}));
	$ex_libs.=' $(PORTSDK_LIBPATH)/portlib.lib'	if (defined($ENV{'PORTSDK_LIBPATH'}));
	$ex_libs.=' /nodefaultlib:oldnames.lib coredll.lib corelibc.lib' if ($ENV{'TARGETCPU'} eq "X86");
	}
else
	{
	$ex_libs.=' gdi32.lib advapi32.lib crypt32.lib user32.lib';
	$ex_libs.=' bufferoverflowu.lib' if ($FLAVOR =~ /WIN64/ and `cl 2>&1` =~ /14\.00\.4[0-9]{4}\./);
	# WIN32 UNICODE build gets linked with unicows.lib for
	# backward compatibility with Win9x.
	$ex_libs="unicows.lib $ex_libs" if ($FLAVOR =~ /WIN32/ and $cflags =~ /\-DUNICODE/);
	}

# static library stuff
$mklib='lib /nologo';
$ranlib='';
$plib="";
$libp=".lib";
$shlibp=($shlib)?".dll":".lib";
$lfile='/out:';

$shlib_ex_obj="";
$app_ex_obj="setargv.obj" if ($FLAVOR !~ /CE/);
if ($FLAVOR =~ /WIN64A/) {
	if (`nasm -v 2>NUL` =~ /NASM version ([0-9]+\.[0-9]+)/ && $1 >= 2.0) {
		$asm='nasm -f win64 -DNEAR -Ox -g';
		$afile='-o ';
	} else {
		$asm='ml64 /c /Cp /Cx /Zi';
		$afile='/Fo';
	}
} elsif ($FLAVOR =~ /WIN64I/) {
	$asm='ias -d debug';
	$afile="-o ";
} elsif ($nasm) {
	my $ver=`nasm -v 2>NUL`;
	my $vew=`nasmw -v 2>NUL`;
	# pick newest version
	$asm=($ver ge $vew?"nasm":"nasmw")." -f win32";
	$asmtype="win32n";
	$afile='-o ';
} else {
	$asm='ml /nologo /Cp /coff /c /Cx /Zi';
	$afile='/Fo';
	$asmtype="win32";
}

$bn_asm_obj='';
$bn_asm_src='';
$des_enc_obj='';
$des_enc_src='';
$bf_enc_obj='';
$bf_enc_src='';

if (!$no_asm)
	{
	win32_import_asm($mf_bn_asm, "bn", \$bn_asm_obj, \$bn_asm_src);
	win32_import_asm($mf_aes_asm, "aes", \$aes_asm_obj, \$aes_asm_src);
	win32_import_asm($mf_des_asm, "des", \$des_enc_obj, \$des_enc_src);
	win32_import_asm($mf_bf_asm, "bf", \$bf_enc_obj, \$bf_enc_src);
	win32_import_asm($mf_cast_asm, "cast", \$cast_enc_obj, \$cast_enc_src);
	win32_import_asm($mf_rc4_asm, "rc4", \$rc4_enc_obj, \$rc4_enc_src);
	win32_import_asm($mf_rc5_asm, "rc5", \$rc5_enc_obj, \$rc5_enc_src);
	win32_import_asm($mf_md5_asm, "md5", \$md5_asm_obj, \$md5_asm_src);
	win32_import_asm($mf_sha_asm, "sha", \$sha1_asm_obj, \$sha1_asm_src);
	win32_import_asm($mf_rmd_asm, "ripemd", \$rmd160_asm_obj, \$rmd160_asm_src);
	win32_import_asm($mf_wp_asm, "whrlpool", \$whirlpool_asm_obj, \$whirlpool_asm_src);
	win32_import_asm($mf_cpuid_asm, "", \$cpuid_asm_obj, \$cpuid_asm_src);
	$perl_asm = 1;
	}

if ($shlib && $FLAVOR !~ /CE/)
	{
	$mlflags.=" $lflags /dll";
	$lib_cflag.=" -D_WINDLL";
	#
	# Engage Applink...
	#
	$app_ex_obj.=" \$(OBJ_D)\\applink.obj /implib:\$(TMP_D)\\junk.lib";
	$cflags.=" -DOPENSSL_USE_APPLINK -I.";
	# I'm open for better suggestions than overriding $banner...
	$banner=<<'___';
	@echo Building OpenSSL

$(OBJ_D)\applink.obj:	ms\applink.c
	$(CC) /Fo$(OBJ_D)\applink.obj $(APP_CFLAGS) -c ms\applink.c
$(OBJ_D)\uplink.obj:	ms\uplink.c ms\applink.c
	$(CC) /Fo$(OBJ_D)\uplink.obj $(SHLIB_CFLAGS) -c ms\uplink.c
$(INCO_D)\applink.c:	ms\applink.c
	$(CP) ms\applink.c $(INCO_D)\applink.c

EXHEADER= $(EXHEADER) $(INCO_D)\applink.c

LIBS_DEP=$(LIBS_DEP) $(OBJ_D)\applink.obj
CRYPTOOBJ=$(OBJ_D)\uplink.obj $(CRYPTOOBJ)
___
	$banner.=<<'___' if ($FLAVOR =~ /WIN64/);
CRYPTOOBJ=ms\uptable.obj $(CRYPTOOBJ)
___
	}
elsif ($shlib && $FLAVOR =~ /CE/)
	{
	$mlflags.=" $lflags /dll";
	$lflags.=' /entry:mainCRTstartup' if(defined($ENV{'PORTSDK_LIBPATH'}));
	$lib_cflag.=" -D_WINDLL -D_DLL";
	}

sub do_lib_rule
	{
	my($objs,$target,$name,$shlib,$ign,$base_addr) = @_;
	local($ret);

	$taget =~ s/\//$o/g if $o ne '/';
	my $base_arg;
	if ($base_addr ne "")
		{
		$base_arg= " /base:$base_addr";
		}
	else
		{
		$base_arg = "";
		}
	if ($name ne "")
		{
		$name =~ tr/a-z/A-Z/;
		$name = "/def:ms/${name}.def";
		}

#	$target="\$(LIB_D)$o$target";
#	$ret.="$target: $objs\n";
	if (!$shlib)
		{
#		$ret.="\t\$(RM) \$(O_$Name)\n";
		$ret.="$target: $objs\n";
		$ret.="\t\$(MKLIB) $lfile$target @<<\n  $objs\n<<\n";
		}
	else
		{
		local($ex)=($target =~ /O_CRYPTO/)?'':' $(L_CRYPTO)';
		$ex.=" $zlib_lib" if $zlib_opt == 1 && $target =~ /O_CRYPTO/;

 		if ($fips && $target =~ /O_CRYPTO/)
			{
			$ret.="$target: $objs \$(PREMAIN_DSO_EXE)";
			$ret.="\n\tSET FIPS_LINK=\$(LINK)\n";
			$ret.="\tSET FIPS_CC=\$(CC)\n";
			$ret.="\tSET FIPS_CC_ARGS=/Fo\$(OBJ_D)${o}fips_premain.obj \$(SHLIB_CFLAGS) -c\n";
			$ret.="\tSET PREMAIN_DSO_EXE=\$(PREMAIN_DSO_EXE)\n";
			$ret.="\tSET FIPS_SHA1_EXE=\$(FIPS_SHA1_EXE)\n";
			$ret.="\tSET FIPS_TARGET=$target\n";
			$ret.="\tSET FIPSLIB_D=\$(FIPSLIB_D)\n";
			$ret.="\t\$(FIPSLINK) \$(MLFLAGS) $ff /map $base_arg $efile$target ";
			$ret.="$name @<<\n  \$(SHLIB_EX_OBJ) $objs \$(EX_LIBS) ";
			$ret.="\$(OBJ_D)${o}fips_premain.obj $ex\n<<\n";
			}
		else
			{
			$ret.="$target: $objs";
			$ret.="\n\t\$(LINK) \$(MLFLAGS) $efile$target $name @<<\n  \$(SHLIB_EX_OBJ) $objs $ex \$(EX_LIBS)\n<<\n";
			}
		$ret.="\tIF EXIST \$@.manifest mt -nologo -manifest \$@.manifest -outputresource:\$@;2\n\n";
		}
	$ret.="\n";
	return($ret);
	}

sub do_link_rule
	{
	my($target,$files,$dep_libs,$libs,$standalone)=@_;
	local($ret,$_);
	$file =~ s/\//$o/g if $o ne '/';
	$n=&bname($targer);
	$ret.="$target: $files $dep_libs\n";
	if ($standalone == 1)
		{
		$ret.="  \$(LINK) \$(LFLAGS) $efile$target @<<\n\t";
		$ret.= "\$(EX_LIBS) " if ($files =~ /O_FIPSCANISTER/ && !$fipscanisterbuild);
		$ret.="$files $libs\n<<\n";
		}
	elsif ($standalone == 2)
		{
		$ret.="\tSET FIPS_LINK=\$(LINK)\n";
		$ret.="\tSET FIPS_CC=\$(CC)\n";
		$ret.="\tSET FIPS_CC_ARGS=/Fo\$(OBJ_D)${o}fips_premain.obj \$(SHLIB_CFLAGS) -c\n";
		$ret.="\tSET PREMAIN_DSO_EXE=\n";
		$ret.="\tSET FIPS_TARGET=$target\n";
		$ret.="\tSET FIPS_SHA1_EXE=\$(FIPS_SHA1_EXE)\n";
		$ret.="\tSET FIPSLIB_D=\$(FIPSLIB_D)\n";
		$ret.="\t\$(FIPSLINK) \$(LFLAGS) $ff /map $efile$target @<<\n";
		$ret.="\t\$(APP_EX_OBJ) $files \$(OBJ_D)${o}fips_premain.obj $libs\n<<\n";
		}
	else
		{
		$ret.="\t\$(LINK) \$(LFLAGS) $efile$target @<<\n";
		$ret.="\t\$(APP_EX_OBJ) $files $libs\n<<\n";
		}
    	$ret.="\tIF EXIST \$@.manifest mt -nologo -manifest \$@.manifest -outputresource:\$@;1\n\n";
	return($ret);
	}

sub win32_import_asm
	{
	my ($mf_var, $asm_name, $oref, $sref) = @_;
	my $asm_dir;
	if ($asm_name eq "")
		{
		$asm_dir = "crypto\\";
		}
	else
		{
		$asm_dir = "crypto\\$asm_name\\asm\\";
		}

	$$oref = "";
	$mf_var =~ s/\.o$/.obj/g;

	foreach (split(/ /, $mf_var))
		{
		$$oref .= $asm_dir . $_ . " ";
		}
	$$oref =~ s/ $//;
	$$sref = $$oref;
	$$sref =~ s/\.obj/.asm/g;

	}


1;

#!/usr/bin/perl
###################################################
#$Id: execapi.pl 1347 2011-04-21 16:38:12Z vivian $
###################################################
#1. 檢核傳入參數內容及protal type
#2. 做為登入之檢核，並產生sid
#3. 做為sid之檢核
#4. 設定cookies
###################################################
use strict;
use Storable qw(store retrieve);
use HTTP::Date;
use Digest::MD5 qw(md5_hex);

use FindBin qw($Bin);
use lib "$Bin";

#---------------
#公用模組
use chkindata;
use parserdata;
use cardsapi;
use getcfgdata;
use cookies;
use logger;
my $chkindata  = chkindata->new();
my $parserdata = parserdata->new();
my $cardsapi   = cardsapi->new();
my $cookies    = cookies->new();
#---------------
my ( %apinums,%execapi,%apicode,%modules,%apichkok );
my ( %configure_login, %configure_pages, %configure_mail, %configure_system );

sub main 
{
	my ( %IN, %OUT, %OUT2 );

print "Cache-Control: no-cache, no-cache" . "\r\n";
print "Pragma: no-cache, no-cache" . "\r\n";
print "Content-Type: text/html; charset=utf-8" . "\r\n";
print "Connection: close" . "\r\n\r\n";

	#取得client傳進來的值，並取出放入IN哈希中
	&get_datas( \%IN );

	#http://127.0.0.1/api/?sid=sid&api=orgunit_add&datas=[{"ordersqlcmd":"ORDERSQLCMD","qrypage":"QRYPAGE"}{"orgname":"ORGNAME","orgparentpath":"ORGPARENTPATH"}]&restype=json
	my $sid     = $IN{sid};
	my $api     = $IN{api};
	my $datas   = $IN{datas};
	my $restype = $IN{restype};
	
	$api=~s/\r|\n|\s//g;

	$restype = 'json' if ( $restype eq '' );

	#檢核datas(json) --> 格式是否正確
	if ( !$chkindata->chkportaltype( \%IN, \%OUT ) ) {

		#protaltype檢核失敗,直接送出json內容
		$parserdata->parser_json_normal( \%OUT, '' ) if ( $restype =~ /json/i );
		$parserdata->parser_json_funs( \%OUT, '' ) if ( $restype =~ /xml/i );
	}

	my $getcfgdata = getcfgdata->new();
	$getcfgdata->getdatas( \%apinums, \%execapi, \%apicode, \%configure_login, \%configure_pages, \%configure_mail, \%configure_system, \%apichkok );

	#檢核api名稱是否為有效名稱
	&outputmesg( '000016', \%IN ) if !$apinums{$api};
	
	if ( $api =~ /^c_(.*)/i ) {

		#卡務程式api
		#&outputmesg('000011',\%IN) if(! &chksession(\%IN));
		#eval '$cardsapi->'.$api.'(\%IN)';

	} elsif ( $api =~ /^d_(.*)/i ) {

		#門禁程式api
		#&outputmesg('000011',\%IN) if(! &chksession(\%IN));
		#eval '$doorsapi->'.$api.'(\%IN)';

	} else {

		#非卡務＆門禁api

		#api符合 login，不需檢核sid
		if ( $api =~ /login/i )
		{
			eval '$chkindata->' . $api . '(\%IN)';	
		
		}else
		{
			#api != api_login者，需檢核sid
			my $sid_map_uids = $OUT{resmsg};
	
			#sxxx001: 無法取得認證帳號api清單
			&outputmesg( '000008', \%IN ) if ( !-e $sid_map_uids );

			#取出該api帳號的實際檔案存放位置
			#$sid_map_uids = /usr/local/cateye/api/../datas/sids/123456789
			open( my $FH_sid, '<:raw', $sid_map_uids );
			my $uid_paths = do { local $/; <$FH_sid> };
			close($FH_sid);

			#取出該api帳號可以使用api清單
			#$uid_paths = /usr/local/cateye/api/../datas/auths/vivian.uid
			my ( $auth_pwd, $auth_apis );
			open( my $FH_uid_paths, '<:raw', $uid_paths );
			while (<$FH_uid_paths>) 
			{
				$_ =~ s/\r\n|\n//;
				$_ =~ s/\s//g;
				if ( $_ eq '' || $_ =~ /^\#/ ) { next; }
				$_ =~ /(.*):(.*)/;
	
				my $key     = $1;
				my $keyword = $2;
	
				#取出此帳號密碼 ＆ 此帳號可使用的api清單
				$auth_apis = $keyword if $key =~ /apis/i;
			}
			close($FH_uid_paths);

			#sxxx002: 此帳號的api可使用功能列表未被設定
			&outputmesg( '000009', \%IN ) if ( $auth_apis eq '' );
			
			if ( $api =~ /getfuns/i ) 
			{
				#api符合 api_getfuns，不需檢核是否被附予使用api的權限(但已檢核過sid)
				$IN{sid_map_uids} = $OUT{resmsg};
				$IN{auth_apis}    = $auth_apis;
				eval '$chkindata->' . $api . '(\%IN)';
			
			}else
			{
				if ( $auth_apis ne 'all' ) 
				{
					my %api_hash;
					my @api_array = split( /\;/, $auth_apis );
					foreach my $pri_api (@api_array) { $api_hash{$pri_api} = 1; }
		
					#s000010: 此api帳號未被附予登入網站功能的權限
					&outputmesg( '000010', \%IN ) if ( !$api_hash{$api} );
				}

				#api符合 configure_get / auth_login / rebuildpasswd ，不需檢核session(但已檢核過sid,api使用權限)
				if ( $api !~ /authenticate/i )
				{
					&outputmesg('000011',\%IN) if(! &chksession(\%IN));	
				}
				
				#$IN{authuser}='ycj715@tc.program.com.tw';
					
				#api需先檢核session後，才可以call程式(但已檢核過sid,api使用權限)
				my $module;
				eval 'require '.$api.';$module='.$api.'->new();' if($apichkok{$api});
				SWITCH:
				{
				 	#get - 取得設定檔內容
					#setup - 回寫設定檔內容
					eval '$module->'.$api.'(\%IN)'; last SWITCH if($apichkok{$api});
				   	eval '$chkindata->' . $api . '(\%IN)';
				}
			}
		}		
	}
}
main();
1;
#---------------------------------------------------
#檢核cookies/session
sub chksession 
{
	my ($inref) = @_;

open( my $FHx, ">$Bin/0629.log" );
foreach my $key(keys %ENV)
{
	print $FHx "$key-->".$ENV{$key}."\n";
}

	my ( $cookie, $AuthUser );
	my @cookieary = split( '; ', $ENV{'HTTP_COOKIE'} );
	for ( my $i = 0 ; $i <= $#cookieary ; $i++ ) {
		if ( $cookieary[$i] =~ m/Auth\=/ ) {

			#Auth=wYz7BvR4vYXwE&AuthUser=luke
			my @cookietemp = split( /&/, $cookieary[$i] );
			for ( my $ii = 0 ; $ii <= $#cookietemp ; $ii++ ) {
				my @cookiesplit = split( /=/, $cookietemp[$ii] );
				if ( $cookiesplit[0] eq 'Auth' )     { $cookie   = $cookiesplit[1]; }
				if ( $cookiesplit[0] eq 'AuthUser' ) { $AuthUser = $cookiesplit[1]; }
			}
		}
	}
	
	return 0 if ( !$cookies->chkcookies( $cookie, $AuthUser ) );

	$inref->{authuser} = $AuthUser;
	return 1;
}

#取得client傳進來的值，並取出放入IN哈希中
sub get_datas 
{
	my ($INref) = @_;

	my $buffer;
	my @nv_pairs;

	if ( $ENV{REQUEST_METHOD} eq 'GET' ) 
	{
		#GET
		$buffer = $ENV{QUERY_STRING};
		$buffer =~ s/\&amp\;/&/g;

		#$buffer =~ s/%(?:([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))/defined($1)? chr hex($1) : chr hex($2)/ge;
		#api=login&datas=[{%22uid%22:%22auth1%40tc.program.com.tw%22,%22pwd%22:%22vivian%22}]&restype=json
		@nv_pairs = split( /\&/, $buffer );
		foreach my $nvp ( 0 .. $#nv_pairs ) {
			$nv_pairs[$nvp] =~ tr/+/ /;
			my ( $key, $keyword ) = split( /=/, $nv_pairs[$nvp], 2 );
			$key =~ s#%(..)#pack("c",hex($1))#ge;
			$key = lc($key);
			$keyword =~ s/%(?:([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))/defined($1)? chr hex($1) : chr hex($2)/ge;
			$key     =~ tr/\`"'!@#$^*()|; //d;

			$INref->{$key} .= "\0" if ( defined( $INref->{$key} ) );
			$INref->{$key} .= $keyword;
		}
	} elsif ( $ENV{REQUEST_METHOD} eq 'POST' ) 
	{
		#POST - 上傳檔案
		if($ENV{CONTENT_TYPE}=~/multipart\/form-data/i)
		{
			my $content_type = $ENV{CONTENT_TYPE};
			#另一種模式
			#------WebKitFormBoundaryp7a4Evpes7k00uwu
			#Content-Disposition: form-data; name="file"; filename="1116_3"
			#Content-Type: application/octet-stream
			#
			#流水號     卡號
			#＝＝＝＝＝＝＝＝＝＝＝
			#000469    4EA6BF33
			#000470    4EA6BF43
			#000471    4EA6BF53
			#000472    D029708B
			#000473    D029AE7B
			#000474    D029AEAB
			#
			#------WebKitFormBoundaryp7a4Evpes7k00uwu
			#Content-Disposition: form-data; name="filedesc1"
			#
			#123
			#------WebKitFormBoundaryp7a4Evpes7k00uwu
			#Content-Disposition: form-data; name="filedesc2"
			#
			#455
			#------WebKitFormBoundaryp7a4Evpes7k00uwu--
			my $headerstart = 0;
			my $bodystart   = 0;
			my @name        = ();
			my $nameidx     = 0;
			my $filename    = '';
			my @fn          = ();
			my $retString;

			my ( $junk, $boundary ) = split /=/, $ENV{CONTENT_TYPE}, 2;
			my $contents = join( '', <STDIN> );
			my @contents_ary2 = split( /--$boundary/, $contents );
			for ( my $i = 0 ; $i < $#contents_ary2 ; $i++ ) 
			{
				my $segment = $contents_ary2[$i];
				my ( $header, $content ) = split( "\r\n\r\n", $segment );
				$header =~ s/\r\n//g;
				$content =~ s/\r\n//g;
				
				if ( $header =~ /Content-Disposition: form-data; name=['|"|](.*?)['|"|]; filename=['|"|](.*?)['|"|]/i ) 
				{
					$name[$nameidx] = $1;
					my $pathfilename = $2;
					if ( $pathfilename ne '' && $content ne '' ) 
					{
						$pathfilename =~ s/\\/\//gs;
						my @ary = split( '/', $pathfilename );
						$filename = $ary[$#ary];
						$filename =~ s/ /_/gs;
						$fn[$nameidx] = $filename;
						$pathfilename = '';
					}
					$nameidx++;

					$content =~ s/\r\n$//;

					if ( $filename ne '' ) 
					{
						my $tmp_folder = $Bin.'/../tmp';
						if(!-e $tmp_folder)
						{
							mkdir $tmp_folder;
							chmod 0750, $tmp_folder;
						}
						
						my $pack_filename1 = md5_hex($filename);
						my $pack_filename2 = $pack_filename1 . '.filename';

						my $upload_file_md5  = $Bin . '/../tmp/' . $pack_filename1;
						my $upload_file_name = $Bin . '/../tmp/' . $pack_filename2;

						#產生上傳檔案
						open( my $HANDLE1, '>:raw', $upload_file_md5 );
						binmode($HANDLE1);
						print $HANDLE1 $content;
						close($HANDLE1);
						chmod 0750, $upload_file_md5;

						#記錄上傳檔案實際檔名
						open( my $HANDLE2, '>:raw', $upload_file_name );
						binmode($HANDLE2);
						print $HANDLE2 $filename;
						close($HANDLE2);
						chmod 0750, $upload_file_name;

						#$INref->{$1} .= "\0" if ( defined( $INref->{$1} ) );
						#$INref->{$1} .= $pack_filename1;
						$INref->{upfilemd5} .= "\0" if ( defined( $INref->{upfilemd5} ) );
						$INref->{upfilemd5} .= $pack_filename1;
					}

				} elsif ( $header =~ /Content-Disposition: form-data; name=['|"|](.*?)['|"|]/i ) 
				{
					$INref->{$1} .= "\0" if ( defined( $INref->{$1} ) );
					$INref->{$1} .= $content;
				}
			}	
		} else 
		{
			#POST
			binmode(STDIN);
			read( STDIN, $buffer, $ENV{'CONTENT_LENGTH'} );
			$buffer =~ s/\&amp\;/&/g;
			@nv_pairs = split( /\&/, $buffer );
			foreach my $nvp ( 0 .. $#nv_pairs ) 
			{
				$nv_pairs[$nvp] =~ tr/+/ /;
				my ( $key, $keyword ) = split( /=/, $nv_pairs[$nvp], 2 );
				$key =~ s#%(..)#pack("c",hex($1))#ge;
				$key = lc($key);
				$keyword =~ s/%(?:([0-9a-fA-F]{2})|u([0-9a-fA-F]{4}))/defined($1)? chr hex($1) : chr hex($2)/ge;
				$key     =~ tr/\`"'!@#$^*()|; //d;

				$INref->{$key} .= "\0" if ( defined( $INref->{$key} ) );
				$INref->{$key} .= $keyword;
			}
		}	
	}
}

sub outputmesg 
{
	my ( $rescode, $INref ) = @_;

	my %OUT;

	$OUT{retcode} = '0';

	#$OUT{rescode}='s'.$apinums{$INref->{api}}.$rescode;
	$OUT{rescode} = 's' . $rescode;
	$OUT{resmsg}  = $apicode{ $OUT{rescode} };

	#protaltype檢核失敗,直接送出json內容
	$parserdata->parser_json_normal( \%OUT ) if ( $INref->{restype} =~ /json/i );
	$parserdata->parser_json_funs( \%OUT )   if ( $INref->{restype} =~ /xml/i );
}

sub set_cookies 
{
	#root=/usr/local/witchery/[settle/branch]/web/api
	#uid=admin
	my ($uid) = @_;

	my %hash1;
	my %hash2;
	my %hash3;

	#root    = /usr/local/witchery/[settle/branch]/web/api
	#cookies = /usr/local/witchery/[settle/branch]/web/api/../../cookies
	#建置cookies目錄(/usr/local/settle/cookies)	~  總帳
	if ( !-e $Bin . '/../../conf/cookies' ) {
		mkdir( $Bin . '/../../conf/cookies' );
		chmod 0750, $Bin . '/../../conf/cookies';
	}

	#cookies     = /usr/local/witchery/[settle/branch]/web/api/../../cookies
	#cookies2uid = /usr/local/witchery/[settle/branch]/web/api/../../cookies/vivian
	#在cookies目錄下以登入帳號建立子目錄
	if ( !-e $Bin . '/../../conf/cookies/' . $uid ) {
		mkdir( $Bin . '/../../conf/cookies/' . $uid );
		chmod 0750, $Bin . '/../../conf/cookies/' . $uid;
	}

	#登入成功交易序號
	my $transid = join( '', ( 0 .. 9, 'A' .. 'Z', 'a' .. 'z' )[ rand 62, rand 62, rand 62, rand 62, rand 62 ] );
	$hash1{$uid} = $transid;

	#帳號cookies
	my $salt = join( '', ( 0 .. 9, 'A' .. 'Z', 'a' .. 'z' )[ rand 62, rand 62 ] );
	my $session = crypt( "AuthPassed", $salt );
	$hash2{$uid} = $session;

	#帳號登入時間
	my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) = localtime(time);
	$mon++;
	my $login_nowtime = ( $year + 1900 ) . sprintf( "%02d", $mon ) . sprintf( "%02d", $mday ) . sprintf( "%02d", $hour ) . sprintf( "%02d", $min ) . sprintf( "%02d", $sec );
	$hash3{$uid} = str2time($login_nowtime);
}

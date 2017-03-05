Summary:        media forward software
Name:           rtpp 
Version:        3.0
Release:        0.0
License:        BSD 
Vendor:         boll_tan
Group:          Applications/Internet
Source:         rtpp 


%description
	 rtpp software is media forward, developmented by gldx
%prep
	
%build
	
%install
	if [ $CENTOS_VER = 6.5 ] || [ $CENTOS_VER = 6.2 ] || [ $CENTOS_VER = 6.3 ] || [ $CENTOS_VER = 6.7 ] || [ $CENTOS_VER = 6.8 ]; then
        install -d $RPM_BUILD_ROOT/usr/local/sbin/
        install -m 755 /usr/local/sbin/rtpp  $RPM_BUILD_ROOT/usr/local/sbin/
        install -m 755 /usr/local/sbin/rtpp_monitor.sh  $RPM_BUILD_ROOT/usr/local/sbin/
        chmod +x $RPM_BUILD_ROOT/usr/local/sbin/rtpp
        chmod +x $RPM_BUILD_ROOT/usr/local/sbin/rtpp_monitor.sh
        install -d $RPM_BUILD_ROOT/etc/init.d/
        install -m 755 $RTPP_APP_DIR/install/rtppmon $RPM_BUILD_ROOT/etc/init.d/
        chmod +x $RPM_BUILD_ROOT/etc/init.d/rtppmon
        install -d $RPM_BUILD_ROOT/lib64/
        install -m 755 $RTPP_APP_DIR/install/libmixer_all.so $RPM_BUILD_ROOT/lib64/
#        install -m 755 $RTPP_APP_DIR/install/libFecProcess.so $RPM_BUILD_ROOT/lib64/		
#        install -d $RPM_BUILD_ROOT/root/.rtpp/profile
#	install -m 755 $RTPP_APP_DIR/install/profile/rtpp.conf $RPM_BUILD_ROOT/root/.rtpp/profile
#        install -m 755 $RTPP_APP_DIR/install/profile/ping.conf $RPM_BUILD_ROOT/root/.rtpp/profile
	
        install -d $RPM_BUILD_ROOT/root/.rtpp/voice
        install -m 755 $RTPP_APP_DIR/install/voice/*.g729 $RPM_BUILD_ROOT/root/.rtpp/voice/
        #install -d /opt/cb/
        #install -m 755 $COMM_DIR/nf_fwd/nf_fwd.ko /opt/cb/
        #-@chkconfig --level 344 cbmon on
	fi	

%files
#/root/.rtpp/profile
	/root/.rtpp/voice/*.g729
#	/opt/cb/nf_fwd.ko
	/usr/local/sbin/rtpp
	/usr/local/sbin/rtpp_monitor.sh
	/etc/init.d/rtppmon
	/lib64/libmixer_all.so

%clean
	cd ${RTPP_APP_DIR}

	CPU_T=`uname -m`
	if [ $CPU_T = i686 ];then
	CPU_T=i386
	fi

	if [ $CENTOS_VER = 6.5 ] || [ $CENTOS_VER = 6.2 ] || [ $CENTOS_VER = 6.3 ] || [ $CENTOS_VER = 6.7 ] || [ $CENTOS_VER = 6.8 ]; then
		mv /root/rpmbuild/RPMS/$CPU_T/rtpp-*.rpm ./
	else
		mv /usr/src/redhat/RPMS/$CPU_T/rtpp-*.rpm ./
	fi

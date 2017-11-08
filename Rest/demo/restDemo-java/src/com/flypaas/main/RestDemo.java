package com.flypaas.main;

import com.flypaas.constant.Constant;
import com.flypaas.rest.RestSDK;

public class RestDemo {
	public static void main(String[] args) {
		RestSDK.createSDKID(Constant.accountSid,Constant.token, Constant.appId);//请将Constant类更换相对应的参数，原参数不可用
	}
}

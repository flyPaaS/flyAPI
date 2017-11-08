package com.flypaas.rest;

public class RestSDK {
	/**
	 * 创建正式应用SDKID
	 * @param accountSid
	 * @param authToken
	 * @param appId
	 * @return
	 */
	public static String createSDKID (String accountSid,String authToken,String appId){
		String result = null ;
		try {
			result=new JsonReqSDK().createSDKID(accountSid, authToken, appId);
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("--------------------------生成SDKID失败------------------------");
			System.out.println(e.getMessage());
		}
		System.out.println("SDKID："+result);
		return result ;
	}
}

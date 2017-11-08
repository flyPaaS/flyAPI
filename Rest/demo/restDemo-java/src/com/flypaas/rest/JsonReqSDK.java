package com.flypaas.rest;
import java.io.ByteArrayInputStream;
import java.util.Date;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;

import com.flypaas.constant.Constant;
import com.flypaas.entity.RestSDK;
import com.flypaas.utils.DateUtil;
import com.flypaas.utils.EncryptUtil;
import com.flypaas.utils.JsonUtil;
public class JsonReqSDK{
	/**
	 * post方式创建SDKID
	 * @param accountSid
	 * @param authToken
	 * @param appId
	 * @return
	 */
	public String createSDKID(String accountSid, String authToken, String appId) {
		String result = "";
		try {
			//构造请求URL内容
			String timestamp = DateUtil.dateToStr(new Date(), DateUtil.DATE_TIME_NO_SLASH);
			String url = buildUrl(accountSid, authToken, appId, timestamp,Constant.function_operation);
			System.out.println("请求 url:"+url);
			RestSDK restSDK=new RestSDK();
			restSDK.setAppId(appId);
			String body = "{\"SDK\":"+JsonUtil.toJsonStr(restSDK)+"}";
			System.out.println("---------------------------创建SDKID参数串-------------------------");
			System.out.println(body);
			HttpResponse response=post("application/json",accountSid, authToken, timestamp, url, body);
			//获取响应实体信息
			HttpEntity entity = response.getEntity();
			if (entity != null) {
				result = EntityUtils.toString(entity, "UTF-8");
			}
			System.out.println("---------------------------返回实体信息-------------------------");
			System.out.println(result);
			// 确保HTTP响应内容全部被读出或者内容流被关闭
			EntityUtils.consume(entity);
		}catch (Exception e) {
			System.out.println("---------------------------创建SDKID失败-------------------------");
			System.out.println(e.getMessage());
		}
		return result;
	}
	/**
	 * 
	 * @param accountSid
	 * @param authToken
	 * @param appId
	 * @param timestamp
	 * @param prUrl   即 "/{function}/{operation}"
	 * @return
	 * @throws Exception
	 */
	public String buildUrl(String accountSid, String authToken, String appId,String timestamp,String prUrl) throws Exception{
		//MD5加密
		EncryptUtil encryptUtil = new EncryptUtil();
		String signature =getSignature(accountSid,authToken,timestamp,encryptUtil);
		String url = new StringBuffer(Constant.restAddress).append("/").append(Constant.version)
				.append("/Accounts/").append(accountSid)
				.append(prUrl)
				.append("?sig=").append(signature).toString();
		return url;
	}
	
	/**
	 * 生成sig
	 * @param accountSid
	 * @param authToken
	 * @param timestamp
	 * @param encryptUtil
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("static-access")
	public String getSignature(String accountSid, String authToken,String timestamp,EncryptUtil encryptUtil) throws Exception{
		//md5(主账户Id +主账户授权令牌 + 时间戳)
		String sig = accountSid + authToken + timestamp;
		String signature = encryptUtil.md5Digest(sig);
		return signature;
	}
	
	@SuppressWarnings("static-access")
	public HttpResponse post(String cType,String accountSid,String authToken,String timestamp,String url,String body) throws Exception{
		DefaultHttpClient httpclient = new DefaultHttpClient();
		EncryptUtil encryptUtil = new EncryptUtil();
		//创建HttpPost
		HttpPost httppost = new HttpPost(url);
		httppost.setHeader("Accept", cType);
		httppost.setHeader("Content-Type", cType+";charset=utf-8");
		String src = accountSid + ":" + timestamp;
		// base64(主账户Id + 冒号 +时间戳)
		String auth = encryptUtil.base64Encoder(src);
		httppost.setHeader("Authorization", auth);
		System.out.println("---------------------------- find account for xml begin----------------------------");
		System.out.println("Response content is: " + body);
		BasicHttpEntity requestBody = new BasicHttpEntity();
        requestBody.setContent(new ByteArrayInputStream(body.getBytes("UTF-8")));
        requestBody.setContentLength(body.getBytes("UTF-8").length);
        httppost.setEntity(requestBody);
        // 执行客户端请求
		HttpResponse response = httpclient.execute(httppost);
		httpclient.getConnectionManager().shutdown();
		return response;
	}
}

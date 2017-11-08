package com.kct.restdemo.rest;

import android.annotation.SuppressLint;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by zhouwq on 2017/3/8/008.
 * 和rest服务器交互接口
 */

public class RestHttpClient {
    // 版本
    private String version = "2017-03-28";

    // 获取rest服务器地址
    private StringBuffer getUrl() {
        return new StringBuffer("http://60.205.137.243:80");
    }

    // 登录rest服务器获取测试client id
    public String applySdkId(String strSid, String token, String appId) {
        String result = "";
        DefaultHttpClient httpclient = new DefaultHttpClient();
        try {
            // 构造请求URL内容
            EncryptUtil encryptUtil = new EncryptUtil();
            String timestamp = DateToStr();
            String signature = getSignature(strSid, token, timestamp, encryptUtil);
            String url = getUrl().append("/").
                    append(version).
                    append("/Accounts/").
                    append(strSid).
                    append("/applySDKID?sig=").
                    append(signature).toString();

            JSONObject json = new JSONObject();
            JSONObject account = new JSONObject();
            account.put("appId", appId);
            json.put("SDK", account);

            HttpResponse response = post(strSid, timestamp, url, httpclient, encryptUtil, json.toString());
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                result = EntityUtils.toString(entity, "UTF-8");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 关闭连接
            httpclient.getConnectionManager().shutdown();
        }
        return result;
    }

    // Get方式去申请rest服务器
    private HttpResponse get(String accountSid, String timestamp,
                            String url, DefaultHttpClient httpclient, EncryptUtil encryptUtil) throws Exception {
        HttpGet httpGet = new HttpGet(url);
        httpGet.setHeader("Accept", "application/json");
        httpGet.setHeader("Content-Type", "application/json;charset=utf-8");
        String src = accountSid + ":" + timestamp;
        String auth = encryptUtil.base64Encoder(src);
        httpGet.setHeader("Authorization", auth);
        return httpclient.execute(httpGet);
    }

    // Post方式去申请rest服务器
    private HttpResponse post(String accountSid, String timestamp,
                             String url, DefaultHttpClient httpclient, EncryptUtil encryptUtil,
                             String body) throws Exception {
        HttpPost httppost = new HttpPost(url);
        httppost.setHeader("Accept", "application/json");
        httppost.setHeader("Content-Type", "application/json;charset=utf-8");
        String src = accountSid + ":" + timestamp;
        String auth = encryptUtil.base64Encoder(src);
        httppost.setHeader("Authorization", auth);
        if (body != null && body.length() > 0) {
            BasicHttpEntity requestBody = new BasicHttpEntity();
            requestBody.setContent(new ByteArrayInputStream(body.getBytes("UTF-8")));
            requestBody.setContentLength(body.getBytes("UTF-8").length);
            httppost.setEntity(requestBody);
        }
        return httpclient.execute(httppost);
    }

    // 获取MD5加密后的数据
    private String getSignature(String accountSid, String authToken,
                               String timestamp, EncryptUtil encryptUtil) throws Exception {
        String sig = accountSid + authToken + timestamp;
        return encryptUtil.md5Digest(sig);
    }

    @SuppressLint("SimpleDateFormat")
    private static String DateToStr() {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
        return formatter.format(new Date());
    }
}

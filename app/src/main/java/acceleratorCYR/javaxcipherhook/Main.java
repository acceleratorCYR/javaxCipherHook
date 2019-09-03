package acceleratorCYR.javaxcipherhook;


import android.os.Looper;
import android.util.Log;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import android.os.Process;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static de.robv.android.xposed.XposedHelpers.callStaticMethod;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import static de.robv.android.xposed.XposedHelpers.getObjectField;
import static de.robv.android.xposed.XposedHelpers.getStaticObjectField;
import java.lang.Byte;
/**
 * Created by test2016 on 2017/8/25.
 */

public class Main implements IXposedHookLoadPackage {

    private String packageName;
    private ClassLoader classLoader;
    private XC_MethodHook methodhookPub;
    private XC_MethodHook methodhookCryptoInit;

    private static String confFileName = "/data/local/tmp/cipher_monitor.conf";

    private boolean tryHookMethodByName(String className, String methodName)
    {
        try {
            Class<?> classNeedHook = classLoader.loadClass(className);
            Method[] deMethods = classNeedHook.getDeclaredMethods();

            for(Method deMethod:deMethods)
            {
                //XposedBridge.log(deMethod.getName());
                if(methodName.equals(deMethod.getName()))
                {
                    //XposedBridge.log("start to hook method :" +className + "#"+ methodName);
                    //XposedBridge.log("start to hook method :" +className + "#"+ methodName);
                    XposedBridge.hookMethod(deMethod, methodhookPub);

                }
            }

            return true;
        }catch(ClassNotFoundException e)
        {
            e.printStackTrace();
        }

        return false;

    }

    private boolean tryHookMethodByNameWithMethod(String className, String methodName, XC_MethodHook methodhook)
    {
        try {
            Class<?> classNeedHook = classLoader.loadClass(className);
            Method[] deMethods = classNeedHook.getDeclaredMethods();

            for(Method deMethod:deMethods)
            {
                //XposedBridge.log(deMethod.getName());
                if(methodName.equals(deMethod.getName()))
                {
                    //XposedBridge.log("start to hook method :" +className + "#"+ methodName);
                    //XposedBridge.log("start to hook method :" +className + "#"+ methodName);
                    XposedBridge.hookMethod(deMethod, methodhook);

                }
            }

            return true;
        }catch(ClassNotFoundException e)
        {
            e.printStackTrace();
        }

        return false;

    }

    private boolean tryHookConstructorsByName(String className)
    {
        try {
            Class<?> classNeedHook = classLoader.loadClass(className);

            XposedBridge.hookAllConstructors(classNeedHook, methodhookPub);

            return true;
        }catch(ClassNotFoundException e)
        {
            e.printStackTrace();
        }

        return false;

    }

    protected void tryToHookProgram(XC_LoadPackage.LoadPackageParam loadPackageParam, String tmpString) {
        if(tmpString.equals(loadPackageParam.packageName))
        {
            packageName = loadPackageParam.packageName;
            Log.d("cyr_" + loadPackageParam.packageName, " start to hook " + packageName);

            classLoader = loadPackageParam.classLoader;
            methodhookPub = new CryptoMethodHook(packageName, classLoader);

            methodhookCryptoInit = new CryptoInitMethodHook(packageName, classLoader);
//
//            XC_MethodHook methodhook = new XC_MethodHook(){
//                @Override
//                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
//
//                    //XposedBridge.log("surprice!!! call LogD");
//                    String output = String.format("%s %s %s %d %d %d %d %s", param.args);
//                    Log.d("cyrMonitorLog " + packageName, output);
//
//                    super.beforeHookedMethod(param);
//                }
//
//                @Override
//                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
//                    super.afterHookedMethod(param);
//                }
//            };

            tryHookMethodByName("javax.crypto.Cipher", "doFinal");
            tryHookMethodByName("javax.crypto.Cipher", "update");
            //try hook HttpGet HttpPost
            //Http


            tryHookMethodByNameWithMethod("javax.crypto.Cipher", "init", methodhookCryptoInit);

        }
    }

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {


        File file = new File(confFileName);
        BufferedReader reader = null;
        try{
            reader = new BufferedReader(new FileReader(file));
            String tmpString = null;

            while((tmpString = reader.readLine()) != null)
            {
                if(tmpString.trim().length() > 0)
                tryToHookProgram(loadPackageParam, tmpString.trim());
            }
            reader.close();
        }catch(IOException e){
            Log.e("cyr", "read conf file error!");
        }finally {
            if(reader != null)
                try{
                    reader.close();
                }catch(IOException e1)
                {

                }
        }
    }
}

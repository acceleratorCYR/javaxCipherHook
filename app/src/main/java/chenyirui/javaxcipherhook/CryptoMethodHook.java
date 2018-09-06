package chenyirui.javaxcipherhook;

import android.util.Log;

import java.lang.reflect.Field;
import java.security.AlgorithmParameters;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import static de.robv.android.xposed.XposedHelpers.getObjectField;

/**
 * Created by test2016 on 2017/11/30.
 */

public class CryptoMethodHook extends XC_MethodHook {

    private String packageName;
    private ClassLoader classLoader;

    private String tag;

    public CryptoMethodHook(String packageName, ClassLoader classLoader){
        this.packageName = packageName;
        this.classLoader = classLoader;
        tag = "cyrmethod " + packageName;
    }


    protected boolean tryGetEncDecInfo(StringBuffer stackOutput,MethodHookParam param){

        try {
            if (param.thisObject != null && param.thisObject instanceof Cipher) {
                //StringBuffer cryptoInfo=new StringBuffer("Algorithm");
                stackOutput.append("\nAlgorithm ");
                Cipher cipher = (Cipher) param.thisObject;
                stackOutput.append(cipher.getAlgorithm() + "    IV: ");
                byte[] iv = cipher.getIV();

                OutputByteArray(stackOutput, iv);

                if (cipher != null) {
                    Field flds = cipher.getClass().getDeclaredField("mode");
                    if (flds != null) {
                        flds.setAccessible(true);
                        int mode = flds.getInt(cipher);
                        stackOutput.append(" OpMode: ");
                        if (mode == 1)
                            stackOutput.append("ENCRYPT_MODE/PUBLIC_KEY ");
                        if (mode == 2)
                            stackOutput.append("DECRYPT_MODE/PRIVATE_KEY ");
                        if (mode == 3)
                            stackOutput.append("SECRET_KEY ");
                        if (mode == 4)
                            stackOutput.append("UNWRAP_MODE ");
                        if (mode == 5)
                            stackOutput.append("WRAP_MODE ");

                    }

                    Field fld = cipher.getClass().getDeclaredField("spiImpl");
                    fld.setAccessible(true);
                    CipherSpi spiImpl = (CipherSpi) fld.get(cipher);
                    //AlgorithmParameters alparams = cipher.getParameters();

                    stackOutput.append("\n spiImpl :"+ spiImpl.getClass().getName() +"\n");
                    Log.i(tag, cipher.getAlgorithm() + " " + spiImpl.getClass().getName());

                    if(spiImpl != null && spiImpl.getClass().getName().indexOf("bouncycastle") >= 0)
                    {

                        if(spiImpl.getClass().getName().indexOf("RC") >= 0){
                            Object rcCipher = getObjectField(spiImpl, "cipher");
                            if(rcCipher == null) {
                                stackOutput.append("\n RC cipher is null");
                                return true;
                            }

                            byte[] workingKey = (byte[])getObjectField(rcCipher, "workingKey");
                            if(workingKey == null)
                            {
                                stackOutput.append("\nRC workingKey = null");
                                return true;
                            }

                            stackOutput.append("RC key: ");
                            OutputByteArray(stackOutput, workingKey);
                            return false;
                        }

                        Object ivParam = getObjectField(spiImpl, "ivParam");
                        if(ivParam == null)
                        {
                            stackOutput.append("\nERROR: get ivParam = null");
                            //Log.e(tag, "get ivParam return NUll : " + spiImpl.getClass().getName());
                            //Throwable thr = new Throwable();
                            //Log.e(tag, "Null ivParam:" + spiImpl.getClass().getName() + "\n" + getStackTracesStr(thr));
                            //XposedBridge.log(getStackTracesStr(thr));
                            return true;
                        }
                        byte[] ivStr = (byte[])getObjectField(ivParam, "iv");

                        stackOutput.append("Bouncycastle: IV: ");
                        OutputByteArray(stackOutput, ivStr);

                        Object parame = getObjectField(ivParam, "parameters");
                        if(parame == null)
                        {
                            Log.w(tag, "get parameters return NUll : " + ivParam.getClass().getName());
                        }

                        byte[] keyStr = (byte[])getObjectField(parame, "key");

                        stackOutput.append(" key: ");
                        OutputByteArray(stackOutput, keyStr);
                    }else{
                        /*
                        stackOutput.append(" here1 \n");

                        Field[] fields =  spiImpl.getClass().getDeclaredFields();
                        for(Field field : fields)
                        {
                            XposedBridge.log(field.getName());
                            stackOutput.append("\t\t " + field.getName()+"\n");
                        }
                        Class<?> tmpClz = spiImpl.getClass();
                        while(true) {
                            tmpClz = tmpClz.getSuperclass();
                            if (tmpClz == null || tmpClz.equals(Object.class)) {
                                break;
                            }


                                Field[] fields1 =  spiImpl.getClass().getDeclaredFields();
                            for(Field field : fields1)
                            {
                                XposedBridge.log(field.getName());
                                stackOutput.append("\t\t " + field.getName()+"\n");
                            }
                        }
                        //Field[] fields = spiImpl.getClass().getFields();
                        for(Field field : fields)
                        {
                            XposedBridge.log(field.getName());
                            stackOutput.append("\t\t " + field.getName()+"\n");
                        }

                        stackOutput.append(" here2 \n");
                        */
                        byte[] encStrbyte = (byte[]) getObjectField(spiImpl, "encodedKey");
                        stackOutput.append("\t\t encodecKey: ");
                        OutputByteArray(stackOutput, encStrbyte);
                    }

                }
            }
        }catch(NoSuchFieldException e){
            //XposedBridge.log(e.toString());
            //Log.w(tag, e.toString());
            stackOutput.append(" \n NoSuchFieldException occurred!\n");
            return true;
        }catch(IllegalAccessException e){
            return true;
        }catch(NoSuchFieldError e)
        {

            stackOutput.append(e.getMessage() + "\nERROR: get field ERROR");
            return true;
            //Log.e(tag, e.getMessage() + getStackTracesStr(e));
        }

        return false;
    }

    protected String getStackTracesStr(Throwable e){
        StackTraceElement []stackTraces = e.getStackTrace();
        String str="";
        if(stackTraces != null)
        {
            for(int i=0; i< stackTraces.length; i++)
            {
                str +=(String.format("\n      : %s #%s :%s",
                        stackTraces[i].getClassName(),
                        stackTraces[i].getMethodName(), stackTraces[i].getLineNumber()));
            }
        }

        return str;
    }


    @Override
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
        //Log.d("cyr" + packageName, "start to hook wechat");

//        Throwable th = new Throwable();
//        StackTraceElement[] stackTraces = th.getStackTrace();
//
//        StringBuffer stackOutput = new StringBuffer(
//                ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\ncyr HookMethodStackTraceBefore  "
//                        + param.getClass().getName());
//
//        if(stackTraces != null)
//        {
//            for(int i=0; i< stackTraces.length; i++)
//            {
//                stackOutput.append(String.format("\n      StackTrace: %s #%s :%s",
//                        stackTraces[i].getClassName(),
//                        stackTraces[i].getMethodName(), stackTraces[i].getLineNumber()));
//            }
//        }
//
//        //Log.i(tag, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
//
//        //Log.i(tag, stackOutput);
//        //StringBuffer outputStr;
//        tryGetEncDecInfo(stackOutput, param);
//
//
//        if(param.args == null)
//            stackOutput.append("\nbefore Call paramsLen: 0" );
//        else {
//            stackOutput.append("\nbefore Call paramsLen:" + param.args.length + " ");
//
//
//            for (int i = 0; i < param.args.length; i++) {
//                if (param.args[i] == null) {
//                    stackOutput.append("\n | param" + Integer.toString(i) + ": "
//                            + "null ");
//                    continue;
//                } else {
//                    stackOutput.append("\n | param" + Integer.toString(i) + ": "
//                            + param.args[i].getClass().getName() + "\t ");
//                }
//
//                //Log.d("cyr tag", String.format("start to analyse param %d", i));
//
//                if (CheckType(param.args[i], String.class)) {
//                    stackOutput.append((String) param.args[i]);
//
//                }
//
//                if (CheckType(param.args[i], byte[].class)) {
//                    OutputByteArray(stackOutput, (byte[]) param.args[i]);
//                }
//
//                if (CheckType(param.args[i], Integer.class)) {
//                    stackOutput.append(Integer.toString((Integer) param.args[i]));
//                } else if (CheckType(param.args[i], int.class)) {
//                    stackOutput.append(Integer.toString((Integer) param.args[i]));
//                }
//            }
//        }
//
//        Log.i(tag, stackOutput.toString());
        super.beforeHookedMethod(param);
    }

    protected boolean CheckType(Object arg, Class<?> clz)
    {
        boolean result;
        if(arg == null)
            return false;
        else {
            try {
                clz.cast(arg);
                result = true;
            }catch(ClassCastException e)
            {
                result = false;
            }
        }

        return result;
    }

    protected void OutputByteArray(StringBuffer outputStr, byte[] param)
    {

        if(param == null) {
            outputStr.append(" null") ;
            return;
        }

        outputStr.append(String.format("length:%d ", param.length));
        for(int bi=0;bi< (param.length>300?300:param.length);bi++) {
            outputStr.append(Integer.toString(param[bi] >> 4 & 0xF, 16));
            outputStr.append(Integer.toString(param[bi] & 0xF, 16));
        }
        String str = new String(param);

        if(str.length() <= 300)
            outputStr.append(" \t" + str);
        else
            outputStr.append(" \t" + str.substring(0,300));

    }

    protected void TryOutputParamOrResult(StringBuffer outputStr,
                                          Object obj, String paramtag, int i) throws Throwable
    {
        if(obj == null)
        {
            outputStr.append("\n | " + paramtag + " " + Integer.toString(i) + ": "
                    +  "null ");
            return;
        }
        else
        {
            outputStr.append( "\n | " + paramtag + " " + Integer.toString(i) + ": "
                    + obj.getClass().getName() + "\t ");
        }

        if(CheckType(obj, String.class))
        {
            outputStr.append((String)obj);

        }

        if(CheckType(obj, byte[].class))
        {
            OutputByteArray( outputStr, (byte[])obj);
        }else if(CheckType(obj, boolean.class))
        {
            outputStr.append((boolean)obj?"true":"false");

        }

        if(CheckType(obj, Integer.class))
        {
            outputStr.append(Integer.toString((Integer)obj));
        }else
        if(CheckType(obj, int.class))
        {
            outputStr.append(Integer.toString((Integer)obj));
        }
    }

    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        super.afterHookedMethod(param);

        Throwable th = new Throwable();
        StackTraceElement[] stackTraces = th.getStackTrace();

        StringBuffer stackOutput = new StringBuffer("cyr HookMethodStackTraceAfter "
                + param.getClass().getName());

        if(stackTraces != null)
        {
            for(int i=0; i< (stackTraces.length < 20? stackTraces.length: 20); i++)
            {
                stackOutput.append(String.format("\n      StackTrace: %s #%s :%s",
                        stackTraces[i].getClassName(),
                        stackTraces[i].getMethodName(), stackTraces[i].getLineNumber()));

            }
            if(stackTraces.length >= 20)
                stackOutput.append("\n   ... ... \n");
        }

        //Log.i(tag, stackOutput.toString());

        Object methodResult = param.getResult();

        boolean outputError = tryGetEncDecInfo(stackOutput, param);

        //StringBuffer outputStr;
        if(param.args == null)
            stackOutput.append("\nafter Call paramsLen: 0 ");
        else {
            stackOutput.append("\nafter Call paramsLen:" + param.args.length + " ");

            for (int i = 0; i < param.args.length; i++) {
                TryOutputParamOrResult(stackOutput, param.args[i], "param", i);

            }
        }
        TryOutputParamOrResult(stackOutput, methodResult, "result", 0);

        stackOutput.append("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        if(outputError)
            Log.e(tag, stackOutput.toString());
        else
            Log.w(tag, stackOutput.toString());
        super.beforeHookedMethod(param);
    }
}

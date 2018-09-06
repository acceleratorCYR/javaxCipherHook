# javaxCipherHook
## Describe
This is used for android device to hook method in apps; It is based on Xposed.

## Usage
1. install this app
2. create file: /data/data/acceleratorCYR.javaxcipherhook/monitor.conf

each line in monitor.conf should be like:
- PackageName classPath MethodName  *#Used to hook method include native function*
- PackageName classPath             *#Used to hook Construct Method*


Example of monitor.conf(it can contains multi lines):
com.accelerator.test com.accelerator.test.Main onCreate
com.accelerator.test com.accelerator.test.Main

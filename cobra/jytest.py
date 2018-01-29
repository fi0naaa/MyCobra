import subprocess
import pdb
p = subprocess.Popen("grep -E '\[输入包文信息打印\]' ~/test/input/log.ls", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
result, error = p.communicate()
print("result = ", result)
print("p = ", p)
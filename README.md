# SM3_length_extend
implement length extension attack for SM3
## 长度扩展攻击原理
<ol>
<li>根据明文的hash值推出第一次压缩之后各个寄存器里的值</li>
<li>在对明文进行填充之后再加上扩展消息得到msg，用上一步寄存器里的值作为IV去加密附加的那段消息，得到hash1</li>
<li>用sm3加密msg，得到hash2</li>
<li>如果hash1=hash2，则说明长度扩展攻击成功</li>
</ol>

## 实验过程
根据实验原理，分别计算hash1和hash2（在代码中对应ext_h与new_h）并输出，若两者相等则长度扩展攻击成功。
其中，SM3的实现参考了<https://github.com/hjzin/SM3LengthExtensionAttack>中my_sm3文件。
## 运行指导
可直接运行
## 结果展示
![image](https://user-images.githubusercontent.com/110109750/182007752-b585b235-2960-4f78-bd10-93abbe571121.png)
## 参考文献
[my_sm3](https://github.com/hjzin/SM3LengthExtensionAttack/blob/master/my_sm3.py)
## 具体贡献说明
除SM3的实现外，其他代码（即main函数中代码）由本人独立完成

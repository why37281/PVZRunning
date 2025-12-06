# PVZRunning

## 简介

如你所见，这是一个阻止PVZ改版崩溃的程序，但是**不只是PVZ！**

作者对于程序作了一些修改，使其可以适配所有程序

目前有两个版本，都针对Windows x64

1. 只是使用此工具防止PVZ改版崩溃，不想重复输入程序名的用户，建议使用`PVZRunning-special.exe`
2. 需要使用此工具防止其他程序崩溃的，需要使用`PVZRunning-all.exe`

目前能力有限，暂时用ai制作

~~提示词提示词用ai要写提示词写完提示词【鲁迅躺在纸堆上燃尽.jpg】~~

## 特性

1. 完全使用C++编写，只由一个文件构成
2. 原理：通过调试器附加源程序，捕捉源程序出现的异常并跳过产生异常的错误
3. 某些异常比如StackOverflow难以避免，能不能处理掉全看天意
4. 对于Special版，程序默认附加`PlantsVsZombies.exe`
5. 对于普适版，程序可以指定附加的程序名，暂时不支持中文名，如果有中文可以改一下被附加的程序名
6. 为了使文件保持小巧，程序只使用了命令行窗口进行交互
7. 程序和被附加的程序不一定要在一个目录下
8. 有美观的消息输出格式，源代码处还有被禁用的字符画
9. 从v0.3-alpha之后，启动程序后（Special版）或者输入被附加的程序名后（普适版），会在程序工作目录下创建`log.txt`，会详细记录时间、附加的程序名、程序事件、程序异常、异常地址和附近的机器码，方便调试。文件最大100KiB,超过自动清空
10. 还有更多，详见代码

## 下一步计划

1. 修复中文程序名无法附加的bug
2. 修复0x406d1388异常无法正确显示的bug

## 协议

作者完全允许修改、发布，但是不允许将本代码用于商业活动。

本项目采用 AGPLv3 许可证授权，并附加禁止商业使用的条款。

- ✅ 您可以自由使用、修改和分发本软件
- ✅ 您必须按照相同的许可证分享您的修改
- ❌ 未经许可，您不得将本软件用于商业目的

详见[LICENSE](LICENSE)文件中的完整内容。

This project is licensed under the AGPLv3 license with additional terms prohibiting commercial use.

- ✅ You can freely use, modify, and distribute this software
- ✅ You must share your modifications under the same license
- ❌ You cannot use this software for commercial purposes without permission

See the [LICENSE](LICENSE) file for full details.

# -*- coding: utf-8 -*-
"""
每 5 秒执行一次 Zoffline 一键社区连通性测试的脚本（无图形界面）。

功能：
- 调用 `Zoffline_CN_Tool_Lib.test_community_connectivity()` 进行测试
- 统计测试通过的次数
- 记录每次测试不通过的时间点

使用方式：
    python connectivity_monitor.py

按 Ctrl + C 终止脚本后，会输出一次汇总统计。
"""

import time
from datetime import datetime

from Zoffline_CN_Tool_Lib import test_community_connectivity


def main():
    passed_count = 0
    failed_count = 0
    failed_times = []  # 记录失败发生的时间（字符串）

    print("开始循环连通性测试（每 5 秒一次）。按 Ctrl + C 结束。\n")

    try:
        while True:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print("=" * 60)
            print(f"[{now}] 开始本次一键连通性测试")

            result = test_community_connectivity()

            if result:
                passed_count += 1
                print(f"[{now}] 本次测试结果：通过")
            else:
                failed_count += 1
                failed_times.append(now)
                print(f"[{now}] 本次测试结果：不通过（已记录时间）")

            print(f"当前统计：通过 {passed_count} 次，不通过 {failed_count} 次")
            print("等待 5 秒后进行下一次测试...\n")
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n检测到用户中断，准备输出统计信息并退出...\n")

    # 汇总统计
    print("=" * 60)
    print("连通性测试汇总结果：")
    print(f"- 总通过次数：{passed_count}")
    print(f"- 总不通过次数：{failed_count}")

    if failed_times:
        print("- 不通过发生时间：")
        for t in failed_times:
            print(f"  * {t}")
    else:
        print("- 测试过程中未出现不通过的情况。")


if __name__ == "__main__":
    main()



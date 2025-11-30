#!/usr/bin/env python3
import os
import sys
import subprocess

sys.dont_write_bytecode = True

def run_script(script_path):
    print(f"\n>>> 正在运行: {script_path}")
    if not os.path.exists(script_path):
        print(f"错误: 找不到文件 {script_path}")
        return False
    
    try:
        result = subprocess.run([sys.executable, script_path], check=True)
        if result.returncode == 0:
            print(f">>> {script_path} 执行成功")
            return True
        else:
            print(f">>> {script_path} 执行失败，返回码: {result.returncode}")
            return False
    except subprocess.CalledProcessError as e:
        print(f">>> 执行出错: {e}")
        return False
    except Exception as e:
        print(f">>> 发生异常: {e}")
        return False

def main():
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    
    step1 = os.path.join(scripts_dir, "aggregate_domains.py")
    if not run_script(step1):
        print("步骤 1 失败，停止执行。")
        return

    step2 = os.path.join(scripts_dir, "adguard_rules.py")
    if not run_script(step2):
        print("步骤 2 失败，停止执行。")
        return

    print("\n=== 所有任务执行完毕 ===")

if __name__ == "__main__":
    main()

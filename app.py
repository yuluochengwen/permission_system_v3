from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap
import pymysql
from pymysql import Error
from typing import List, Dict, Optional
import hashlib
import sys
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'a_random_string_with_enough_length_123'  # 用于会话管理和闪现消息
bootstrap = Bootstrap(app)


class PermissionSystem:
    def __init__(self):
        """初始化数据库连接"""
        try:
            self.connection = pymysql.connect(
                host='localhost',
                user='root',
                password='123456',
                database='my_db',
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            print("\n成功连接到MySQL数据库")
            self._initialize_database()
            if self._should_insert_test_data():
                self._insert_test_data()
        except Error as e:
            print(f"\n错误: 连接MySQL数据库失败: {e}")
            print("请确保:")
            print("1. MySQL服务正在运行")
            print("2. 已创建数据库 'my_db'")
            print("3. 使用 root 用户和密码123456可以访问")
            sys.exit(1)

    def _hash_password(self, password: str) -> str:
        """使用SHA256加密密码"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def _should_insert_test_data(self) -> bool:
        """检查是否需要插入测试数据"""
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM users")
            result = cursor.fetchone()
            return result['count'] == 0

    def _initialize_database(self):
        """确保所有表存在"""
        try:
            with self.connection.cursor() as cursor:
                # 创建权限表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS permissions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    code VARCHAR(100) NOT NULL UNIQUE
                )
                """)

                # 创建角色表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE
                )
                """)

                # 创建角色权限关联表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS role_permissions (
                    role_id INT,
                    permission_id INT,
                    PRIMARY KEY (role_id, permission_id),
                    FOREIGN KEY (role_id) REFERENCES roles(id),
                    FOREIGN KEY (permission_id) REFERENCES permissions(id)
                )
                """)

                # 创建用户表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL
                )
                """)

                # 创建用户角色关联表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id INT,
                    role_id INT,
                    PRIMARY KEY (user_id, role_id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (role_id) REFERENCES roles(id)
                )
                """)

                # 创建功能表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS features (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    code VARCHAR(100) NOT NULL UNIQUE
                )
                """)

                # 创建功能权限关联表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS feature_permissions (
                    feature_id INT,
                    permission_id INT,
                    PRIMARY KEY (feature_id, permission_id),
                    FOREIGN KEY (feature_id) REFERENCES features(id),
                    FOREIGN KEY (permission_id) REFERENCES permissions(id)
                )
                """)

                # 创建员工信息表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS emp_info (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL
                )
                """)

                cursor.execute("DROP TRIGGER IF EXISTS after_emp_info_insert")
                # 添加触发器：当emp_info表插入新记录时，自动向users表插入对应数据
                cursor.execute("""
                CREATE TRIGGER after_emp_info_insert
                AFTER INSERT ON emp_info
                FOR EACH ROW
                BEGIN
                    -- 向users表插入数据，id与emp_info的id一致，password默认123456
                    INSERT INTO users (id, username, password)
                    VALUES (NEW.id, NEW.name, 123456);
                END
                """)

                # 创建考勤规则表（存储上下班时间）
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS attendance_rules (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    work_start_time TIME NOT NULL DEFAULT '09:00:00',  -- 上班时间
                    work_end_time TIME NOT NULL DEFAULT '18:00:00',    -- 下班时间
                    is_default TINYINT(1) NOT NULL DEFAULT 1           -- 是否为默认规则
                )
                """)

                # 创建考勤表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS attendance (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    sign_in_time DATETIME,         -- 上班签到时间
                    sign_out_time DATETIME,        -- 下班签到时间
                    status ENUM('正常', '迟到', '早退', '缺卡', '旷工') NULL,  -- 考勤状态
                    check_date DATE NOT NULL,      -- 考勤日期（用于区分同一天的记录）
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    UNIQUE KEY unique_user_date (user_id, check_date)  -- 确保一人一天一条记录
                )
                """)

            self.connection.commit()
        except Error as e:
            print(f"\n错误: 初始化数据库表失败: {e}")
            self.connection.rollback()

    def _insert_test_data(self):
        """插入测试数据"""
        print("\n正在初始化测试数据...")
        try:
            with self.connection.cursor() as cursor:
                # 清空所有表数据
                tables = ['user_roles', 'role_permissions', 'feature_permissions',
                          'users', 'roles', 'permissions', 'features', 'emp_info',
                          'attendance', 'attendance_rules']
                for table in tables:
                    cursor.execute(f"DELETE FROM {table}")

                # 插入权限
                permissions = [
                    (1001, '创建用户', 'user:create'),
                    (1002, '编辑用户', 'user:update'),
                    (1003, '删除用户', 'user:delete'),
                    (1004, '查看用户', 'user:view'),
                    (1005, '创建角色', 'role:create'),
                    (1006, '分配角色', 'role:assign'),
                    (1007, '管理权限', 'permission:manage'),
                    (1008, '创建员工', 'employees:create'),
                    (1009, '查看员工', 'employees:view'),
                    (1010, '删除员工', 'employees:delete'),
                    (1011, '更新员工', 'employees:update'),
                    (1012, '查看角色', 'role:view'),
                    (1013, '查看考勤', 'attendance:view'),
                    (1014, '管理考勤', 'attendance:manage')
                ]
                cursor.executemany("INSERT INTO permissions (id, name, code) VALUES (%s, %s, %s)", permissions)

                # 插入角色
                roles = [
                    (1001, '系统管理员'),
                    (1002, '普通用户'),
                    (1003, '用户管理员'),
                    (1004, '员工管理员'),
                    (1005, '考勤管理员')
                ]
                cursor.executemany("INSERT INTO roles (id, name) VALUES (%s, %s)", roles)

                # 插入角色权限关联
                role_permissions = [
                    (1001, 1001), (1001, 1002), (1001, 1003), (1001, 1004),
                    (1001, 1005), (1001, 1006), (1001, 1007),
                    (1001, 1008), (1001, 1009), (1001, 1010), (1001, 1011), (1001, 1012),
                    (1001, 1013), (1001, 1014),
                    (1003, 1001), (1003, 1002), (1003, 1004),
                    (1002, 1004), (1002, 1009), (1004, 1008), (1004, 1009), (1004, 1010), (1004, 1011),
                    (1005, 1013), (1005, 1014)
                ]
                cursor.executemany("INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)",
                                   role_permissions)

                # 插入功能
                features = [
                    (1, '用户管理', 'user_management'),
                    (2, '角色管理', 'role_management'),
                    (3, '权限管理', 'permission_management'),
                    (4, '员工管理', 'employee_management')
                ]
                cursor.executemany("INSERT INTO features (id, name, code) VALUES (%s, %s, %s)", features)

                # 插入功能权限关联
                feature_permissions = [
                    (1, 1001), (1, 1002), (1, 1003), (1, 1004),
                    (2, 1005), (2, 1006),
                    (3, 1007),
                    (4, 1008), (4, 1009), (4, 1010), (4, 1011)
                ]
                cursor.executemany("INSERT INTO feature_permissions (feature_id, permission_id) VALUES (%s, %s)",
                                   feature_permissions)

                # 插入默认考勤规则
                cursor.execute("""
                    INSERT INTO attendance_rules (work_start_time, work_end_time, is_default)
                    VALUES ('09:00:00', '18:00:00', 1)
                """)

                # 插入用户(密码使用SHA256加密)
                users = [
                    (1001, 'admin', '123456'),
                    (1002, 'user_manager', '123456'),
                    (1003, 'normal_user', '123456'),
                    (1004, 'employee_manager', '123456')
                ]
                cursor.executemany("INSERT INTO users (id, username, password) VALUES (%s, %s, %s)", users)

                # 插入用户角色关联
                user_roles = [
                    (1001, 1001),
                    (1002, 1003),
                    (1003, 1002),
                    (1004, 1004)
                ]
                cursor.executemany("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", user_roles)

                # 插入测试员工
                employees = [
                    (1005, '张三'),
                    (1006, '李四'),
                    (1007, '王五')
                ]
                cursor.executemany("INSERT INTO emp_info (id, name) VALUES (%s, %s)", employees)
            self.connection.commit()
            print("\n测试数据初始化完成")
            print("默认管理员账号: admin / 123456")
            print("用户管理员账号: user_manager / 123456")
            print("普通用户账号: normal_user / 123456")
            print("员工管理员账号: employee_manager / 123456")
        except Error as e:
            print(f"\n错误: 初始化测试数据失败: {e}")
            self.connection.rollback()
            sys.exit(1)

    # 登录与注册功能
    def login(self, username: str, password: str) -> Optional[Dict]:
        """用户登录"""
        try:
            hashed_password = password
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                if user and user['password'] == hashed_password:
                    return user
                return None
        except Error as e:
            print(f"\n✗ 登录失败: {e}")
            return None

    def register(self, username: str, password: str) -> bool:
        """用户注册"""
        try:
            hashed_password = password
            with self.connection.cursor() as cursor:
                # 检查用户名是否已存在
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return False

                # 创建新用户
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (%s, %s)",
                    (username, hashed_password)
                )

                # 默认分配普通用户角色
                cursor.execute("SELECT id FROM roles WHERE name = '普通用户'")
                role = cursor.fetchone()
                if role:
                    cursor.execute(
                        "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)",
                        (cursor.lastrowid, role['id'])
                    )

            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 注册失败: {e}")
            self.connection.rollback()
            return False

    # 权限检查功能
    def check_permission(self, user_id: int, permission_code: str) -> bool:
        """检查指定用户是否有特定权限"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(1) as permission_count
                    FROM permissions p
                    JOIN role_permissions rp ON p.id = rp.permission_id
                    JOIN user_roles ur ON rp.role_id = ur.role_id
                    WHERE ur.user_id = %s AND p.code = %s
                """, (user_id, permission_code))

                result = cursor.fetchone()
                count = int(result['permission_count']) if result else 0
                return count > 0

        except Error as e:
            print(f"\n✗ 检查权限失败: {e}")
            return False

    # 用户管理功能
    def create_user(self, username: str, password: str) -> bool:
        """创建新用户"""
        try:
            hashed_password = password
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (%s, %s)",
                    (username, hashed_password))
                self.connection.commit()
                return True
        except Error as e:
            print(f"\n✗ 错误: 创建用户失败: {e}")
            self.connection.rollback()
            return False

    def get_users(self) -> List[Dict]:
        """获取所有用户列表"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM users ORDER BY id")
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取用户列表失败: {e}")
            return []

    def delete_user(self, user_id: int) -> bool:
        """删除用户"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                affected = cursor.rowcount
            self.connection.commit()
            return affected > 0
        except Error as e:
            print(f"\n✗ 错误: 删除用户失败: {e}")
            self.connection.rollback()
            return False

    # 角色管理功能
    def create_role(self, role_name: str) -> bool:
        """创建新角色"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("INSERT INTO roles (name) VALUES (%s)", (role_name,))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 创建角色失败: {e}")
            self.connection.rollback()
            return False

    def get_roles(self) -> List[Dict]:
        """获取所有角色列表"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM roles ORDER BY id")
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取角色列表失败: {e}")
            return []

    def assign_role_to_user(self, user_id: int, role_id: int) -> bool:
        """为用户分配角色"""
        try:
            with self.connection.cursor() as cursor:
                # 检查用户和角色是否存在
                cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
                if not cursor.fetchone():
                    return False

                cursor.execute("SELECT id FROM roles WHERE id = %s", (role_id,))
                if not cursor.fetchone():
                    return False

                cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)",
                               (user_id, role_id))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 分配角色失败: {e}")
            self.connection.rollback()
            return False

    # 权限管理功能
    def get_permissions(self) -> List[Dict]:
        """获取所有权限列表"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM permissions ORDER BY id")
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取权限列表失败: {e}")
            return []

    def add_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """为角色添加权限"""
        try:
            with self.connection.cursor() as cursor:
                # 检查角色和权限是否存在
                cursor.execute("SELECT id FROM roles WHERE id = %s", (role_id,))
                if not cursor.fetchone():
                    return False

                cursor.execute("SELECT id FROM permissions WHERE id = %s", (permission_id,))
                if not cursor.fetchone():
                    return False

                cursor.execute("INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)",
                               (role_id, permission_id))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 添加权限失败: {e}")
            self.connection.rollback()
            return False

    def get_user_permissions(self, user_id: int) -> List[Dict]:
        """获取用户的所有权限"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT p.* FROM permissions p
                    JOIN role_permissions rp ON p.id = rp.permission_id
                    JOIN user_roles ur ON rp.role_id = ur.role_id
                    WHERE ur.user_id = %s
                    ORDER BY p.id
                """, (user_id,))
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取用户权限失败: {e}")
            return []

    # 员工管理功能
    def create_employee(self, employee_name: str) -> bool:
        """创建新员工"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("INSERT INTO emp_info (name) VALUES (%s)", (employee_name,))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 创建员工失败: {e}")
            self.connection.rollback()
            return False

    def get_employees(self) -> List[Dict]:
        """获取所有员工列表"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM emp_info ORDER BY id")
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取员工列表失败: {e}")
            return []

    def delete_employee(self, employee_id: int) -> bool:
        """删除员工"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("DELETE FROM emp_info WHERE id = %s", (employee_id,))
                affected = cursor.rowcount
            self.connection.commit()
            return affected > 0
        except Error as e:
            print(f"\n✗ 错误: 删除员工失败: {e}")
            self.connection.rollback()
            return False

    def update_employee(self, employee_id: int, employee_name: str) -> bool:
        """更新员工信息"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("UPDATE emp_info SET name = %s WHERE id = %s", (employee_name, employee_id))
                affected = cursor.rowcount
            self.connection.commit()
            return affected > 0
        except Error as e:
            print(f"\n✗ 错误: 更新员工信息失败: {e}")
            self.connection.rollback()
            return False

    # 考勤规则管理
    def get_attendance_rules(self):
        """获取当前考勤规则（默认取第一条）"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT work_start_time, work_end_time 
                    FROM attendance_rules 
                    WHERE is_default = 1 
                    LIMIT 1
                """)
                rule = cursor.fetchone()

                # 如果没有规则，返回默认时间
                if not rule:
                    return {"work_start_time": "09:00", "work_end_time": "18:00"}  # 改为HH:MM格式

                # 修复：处理时间格式为HH:MM（适配input type="time"）
                def time_to_str(time_obj):
                    if time_obj.__class__.__name__ == 'time':
                        # 只保留小时和分钟，格式化为HH:MM
                        return time_obj.strftime("%H:%M")
                    elif isinstance(time_obj, str):
                        # 如果是字符串，去掉秒数（如从"09:00:00"截取为"09:00"）
                        return time_obj.split(':')[0] + ':' + time_obj.split(':')[1]
                    return "00:00"

                return {
                    "work_start_time": time_to_str(rule['work_start_time']),
                    "work_end_time": time_to_str(rule['work_end_time'])
                }
        except Error as e:
            print(f"\n✗ 错误: 获取考勤规则失败: {e}")
            return {"work_start_time": "09:00", "work_end_time": "18:00"}  # 改为HH:MM格式

    def update_attendance_rules(self, start_time, end_time):
        """更新考勤规则"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("UPDATE attendance_rules SET is_default = 0 WHERE is_default = 1")
                # 即使前端传递HH:MM，数据库会自动补全为HH:MM:00
                cursor.execute("""
                    INSERT INTO attendance_rules (work_start_time, work_end_time, is_default)
                    VALUES (%s, %s, 1)
                """, (start_time, end_time))  # start_time为HH:MM，数据库存储为HH:MM:00
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 更新考勤规则失败: {e}")
            self.connection.rollback()
            return False

    # 考勤签到功能
    def sign_in(self, user_id):
        """上班签到（自动判断是否迟到）"""
        try:
            # 获取当前日期（考虑工作日凌晨签到的情况，凌晨1-6点签到仍算前一天）
            now = datetime.now()
            if now.hour < 6:  # 凌晨6点前签到算前一天
                check_date = (now - timedelta(days=1)).strftime("%Y-%m-%d")
            else:
                check_date = now.strftime("%Y-%m-%d")

            rules = self.get_attendance_rules()
            work_start = datetime.strptime(rules['work_start_time'], "%H:%M").time()

            with self.connection.cursor() as cursor:
                try:
                    # 尝试插入新记录
                    cursor.execute("""
                        INSERT INTO attendance (user_id, sign_in_time, check_date, status)
                        VALUES (%s, NOW(), %s, '正常')
                    """, (user_id, check_date))
                except pymysql.IntegrityError:
                    # 唯一约束冲突，说明当天已有记录，执行更新
                    cursor.execute("""
                        UPDATE attendance
                        SET sign_in_time = NOW()
                        WHERE user_id = %s AND check_date = %s
                    """, (user_id, check_date))

                # 判断是否迟到（签到时间晚于上班时间）
                cursor.execute("""
                    UPDATE attendance
                    SET status = CASE 
                        WHEN TIME(sign_in_time) > %s THEN '迟到'
                        ELSE '正常'
                    END
                    WHERE user_id = %s AND check_date = %s
                """, (work_start, user_id, check_date))

            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 上班签到失败: {e}")
            self.connection.rollback()
            return False

    def sign_out(self, user_id):
        """下班签到（自动判断是否早退）"""
        try:
            # 获取当前日期（与签到逻辑保持一致）
            now = datetime.now()
            if now.hour < 6:  # 凌晨6点前签退算前一天
                check_date = (now - timedelta(days=1)).strftime("%Y-%m-%d")
            else:
                check_date = now.strftime("%Y-%m-%d")

            rules = self.get_attendance_rules()
            work_end = datetime.strptime(rules['work_end_time'], "%H:%M:%S").time()

            with self.connection.cursor() as cursor:
                # 尝试更新签退时间
                cursor.execute("""
                    UPDATE attendance
                    SET sign_out_time = NOW()
                    WHERE user_id = %s AND check_date = %s
                """, (user_id, check_date))

                # 检查是否有更新记录
                if cursor.rowcount == 0:
                    # 没有签到记录，创建一条（缺卡）
                    cursor.execute("""
                        INSERT INTO attendance (user_id, sign_out_time, check_date, status)
                        VALUES (%s, NOW(), %s, '缺卡')
                    """, (user_id, check_date))

                # 判断是否早退（签退时间早于下班时间）
                cursor.execute("""
                    UPDATE attendance
                    SET status = CASE 
                        WHEN TIME(sign_out_time) < %s THEN '早退'
                        WHEN status = '迟到' THEN '迟到'  -- 如果已经是迟到，保持状态
                        ELSE '正常'
                    END
                    WHERE user_id = %s AND check_date = %s
                """, (work_end, user_id, check_date))

            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 下班签到失败: {e}")
            self.connection.rollback()
            return False

    def get_attendance_records(self, user_id=None):
        """获取考勤记录，可指定用户ID，无则获取所有"""
        try:
            with self.connection.cursor() as cursor:
                if user_id:
                    cursor.execute("""
                        SELECT * FROM attendance
                        WHERE user_id = %s
                        ORDER BY check_date DESC
                    """, (user_id,))
                else:
                    cursor.execute("""
                        SELECT a.*, u.username 
                        FROM attendance a
                        JOIN users u ON a.user_id = u.id
                        ORDER BY a.check_date DESC
                    """)
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取考勤记录失败: {e}")
            return []

    def auto_check_absent(self):
        """每日自动检查旷工（可通过定时任务调用）"""
        """检查前一天没有任何签到记录的用户，标记为旷工"""
        try:
            check_date = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
            with self.connection.cursor() as cursor:
                # 获取所有用户
                cursor.execute("SELECT id FROM users")
                users = cursor.fetchall()

                for user in users:
                    user_id = user['id']
                    # 检查该用户当天是否有考勤记录
                    cursor.execute("""
                        SELECT id FROM attendance 
                        WHERE user_id = %s AND check_date = %s
                    """, (user_id, check_date))
                    if not cursor.fetchone():
                        # 无记录，标记为旷工
                        cursor.execute("""
                            INSERT INTO attendance (user_id, check_date, status)
                            VALUES (%s, %s, '旷工')
                        """, (user_id, check_date))

            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 自动检查旷工失败: {e}")
            self.connection.rollback()
            return False

    def get_all_attendance_rules(self):
        """获取所有考勤规则"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM attendance_rules ORDER BY is_default DESC, id")
                return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取所有考勤规则失败: {e}")
            return []

    # def get_attendance_rule(self, rule_id):
    #     """根据ID获取特定考勤规则"""
    #     try:
    #         with self.connection.cursor() as cursor:
    #             cursor.execute("SELECT * FROM attendance_rules WHERE id = %s", (rule_id,))
    #             return cursor.fetchone()
    #     except Error as e:
    #         print(f"\n✗ 错误: 获取考勤规则失败: {e}")
    #         return None

    def get_attendance_rule(self, rule_id):
        """根据ID获取特定考勤规则，并格式化时间为HH:MM"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM attendance_rules WHERE id = %s", (rule_id,))
                rule = cursor.fetchone()

                if rule:
                    # 格式化时间：将datetime.time对象转换为HH:MM字符串
                    # 处理上班时间
                    if isinstance(rule['work_start_time'], datetime.time):
                        rule['work_start_time'] = rule['work_start_time'].strftime("%H:%M")
                    # 处理下班时间
                    if isinstance(rule['work_end_time'], datetime.time):
                        rule['work_end_time'] = rule['work_end_time'].strftime("%H:%M")

                return rule
        except Error as e:
            print(f"\n✗ 错误: 获取考勤规则失败: {e}")
            # 出错时返回默认格式的时间
            return {"work_start_time": "09:00", "work_end_time": "18:00"}

    def set_default_attendance_rule(self, rule_id):
        """设置默认考勤规则"""
        try:
            with self.connection.cursor() as cursor:
                # 先清除所有默认标记
                cursor.execute("UPDATE attendance_rules SET is_default = 0")
                # 设置指定规则为默认
                cursor.execute(
                    "UPDATE attendance_rules SET is_default = 1 WHERE id = %s",
                    (rule_id,)
                )
                if cursor.rowcount == 0:
                    return False
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 设置默认考勤规则失败: {e}")
            self.connection.rollback()
            return False

    def delete_attendance_rule(self, rule_id):
        """删除考勤规则（不能删除最后一条规则）"""
        try:
            with self.connection.cursor() as cursor:
                # 检查是否是最后一条规则
                cursor.execute("SELECT COUNT(*) as count FROM attendance_rules")
                count = cursor.fetchone()['count']
                if count <= 1:
                    return False

                # 检查是否是默认规则
                cursor.execute("SELECT is_default FROM attendance_rules WHERE id = %s", (rule_id,))
                rule = cursor.fetchone()
                if rule and rule['is_default']:
                    # 如果删除的是默认规则，需要设置另一条为默认
                    cursor.execute("SELECT id FROM attendance_rules WHERE id != %s LIMIT 1", (rule_id,))
                    new_default = cursor.fetchone()
                    if new_default:
                        cursor.execute("UPDATE attendance_rules SET is_default = 1 WHERE id = %s", (new_default['id'],))

                # 删除规则
                cursor.execute("DELETE FROM attendance_rules WHERE id = %s", (rule_id,))

            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 删除考勤规则失败: {e}")
            self.connection.rollback()
            return False

    def update_specific_attendance_rule(self, rule_id, start_time, end_time, set_default):
        """更新特定的考勤规则"""
        try:
            with self.connection.cursor() as cursor:
                if set_default:
                    # 如果要设为默认，先清除所有默认标记
                    cursor.execute("UPDATE attendance_rules SET is_default = 0")

                # 更新规则
                cursor.execute("""
                    UPDATE attendance_rules 
                    SET work_start_time = %s, 
                        work_end_time = %s,
                        is_default = %s
                    WHERE id = %s
                """, (start_time, end_time, 1 if set_default else 0, rule_id))

                if cursor.rowcount == 0:
                    return False

            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 更新考勤规则失败: {e}")
            self.connection.rollback()
            return False


    def close(self):
        """关闭数据库连接"""
        if hasattr(self, 'connection') and self.connection.open:
            self.connection.close()


# 初始化系统
system = PermissionSystem()


# 在初始化 system 之后添加
@app.context_processor
def inject_system():
    """将 system 变量注入到所有模板中"""
    return dict(system=system)


# 登录检查装饰器
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('请先登录', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


# 权限检查装饰器
def permission_required(permission_code):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('请先登录', 'danger')
                return redirect(url_for('login', next=request.url))

            user_id = session['user']['id']
            if not system.check_permission(user_id, permission_code):
                flash('您没有执行此操作的权限', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)

        decorated_function.__name__ = f.__name__
        return decorated_function

    return decorator


# 路由
@app.route('/')
def index():
    if 'user' in session:
        return render_template('index.html', user=session['user'])
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = system.login(username, password)

        if user:
            session['user'] = user
            next_page = request.args.get('next', url_for('index'))
            flash('登录成功', 'success')
            return redirect(next_page)
        else:
            flash('用户名或密码错误', 'danger')

    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('两次输入的密码不一致', 'danger')
            return render_template('auth/register.html')

        if system.register(username, password):
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
        else:
            flash('注册失败，用户名可能已存在', 'danger')

    return render_template('auth/register.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('已成功登出', 'success')
    return redirect(url_for('login'))


# 用户管理路由
@app.route('/users')
@login_required
@permission_required('user:view')
def list_users():
    users = system.get_users()
    return render_template('users/list.html', users=users)


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@permission_required('user:create')
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if system.create_user(username, password):
            flash('用户创建成功', 'success')
            return redirect(url_for('list_users'))
        else:
            flash('用户创建失败', 'danger')

    return render_template('users/create.html')


@app.route('/users/delete/<int:user_id>')
@login_required
@permission_required('user:delete')
def delete_user(user_id):
    if system.delete_user(user_id):
        flash('用户删除成功', 'success')
    else:
        flash('用户删除失败', 'danger')
    return redirect(url_for('list_users'))


# 角色管理路由
@app.route('/roles')
@login_required
@permission_required('role:view')  # 新增权限检查
def list_roles():
    roles = system.get_roles()
    return render_template('roles/list.html', roles=roles)


@app.route('/roles/create', methods=['GET', 'POST'])
@login_required
@permission_required('role:create')
def create_role():
    if request.method == 'POST':
        role_name = request.form['role_name']

        if system.create_role(role_name):
            flash('角色创建成功', 'success')
            return redirect(url_for('list_roles'))
        else:
            flash('角色创建失败', 'danger')

    return render_template('roles/create.html')


@app.route('/roles/assign', methods=['GET', 'POST'])
@login_required
@permission_required('role:assign')
def assign_role():
    if request.method == 'POST':
        user_id = int(request.form['user_id'])
        role_id = int(request.form['role_id'])

        if system.assign_role_to_user(user_id, role_id):
            flash('角色分配成功', 'success')
            return redirect(url_for('list_users'))
        else:
            flash('角色分配失败', 'danger')

    users = system.get_users()
    roles = system.get_roles()
    return render_template('roles/assign.html', users=users, roles=roles)


# 权限管理路由
@app.route('/permissions')
@login_required
@permission_required('permission:manage')
def list_permissions():
    permissions = system.get_permissions()
    return render_template('permissions/list.html', permissions=permissions)


@app.route('/permissions/add-to-role', methods=['GET', 'POST'])
@login_required
@permission_required('permission:manage')
def add_permission_to_role():
    if request.method == 'POST':
        role_id = int(request.form['role_id'])
        permission_id = int(request.form['permission_id'])

        if system.add_permission_to_role(role_id, permission_id):
            flash('权限添加成功', 'success')
            return redirect(url_for('list_roles'))
        else:
            flash('权限添加失败', 'danger')

    roles = system.get_roles()
    permissions = system.get_permissions()
    return render_template('permissions/add_to_role.html', roles=roles, permissions=permissions)


@app.route('/users/<int:user_id>/permissions')
@login_required
@permission_required('user:view')
def user_permissions(user_id):
    permissions = system.get_user_permissions(user_id)
    return render_template('users/permissions.html', permissions=permissions, user_id=user_id)


# 员工管理路由
@app.route('/employees')
@login_required
@permission_required('employees:view')
def list_employees():
    employees = system.get_employees()
    return render_template('employees/list.html', employees=employees)


@app.route('/employees/create', methods=['GET', 'POST'])
@login_required
@permission_required('employees:create')
def create_employee():
    if request.method == 'POST':
        employee_name = request.form['name']

        if system.create_employee(employee_name):
            flash('员工创建成功', 'success')
            return redirect(url_for('list_employees'))
        else:
            flash('员工创建失败', 'danger')

    return render_template('employees/create.html')


@app.route('/employees/delete/<int:employee_id>')
@login_required
@permission_required('employees:delete')
def delete_employee(employee_id):
    if system.delete_employee(employee_id):
        flash('员工删除成功', 'success')
    else:
        flash('员工删除失败', 'danger')
    return redirect(url_for('list_employees'))


@app.route('/employees/update/<int:employee_id>', methods=['GET', 'POST'])
@login_required
@permission_required('employees:update')
def update_employee(employee_id):
    if request.method == 'POST':
        employee_name = request.form['name']

        if system.update_employee(employee_id, employee_name):
            flash('员工信息更新成功', 'success')
            return redirect(url_for('list_employees'))
        else:
            flash('员工信息更新失败', 'danger')

    # 获取当前员工信息
    employees = system.get_employees()
    employee = next((e for e in employees if e['id'] == employee_id), None)
    if not employee:
        flash('员工不存在', 'danger')
        return redirect(url_for('list_employees'))

    return render_template('employees/update.html', employee=employee)


# 签到路由
@app.route('/attendance/sign_in')
@login_required
def attendance_sign_in():
    user_id = session['user']['id']
    if system.sign_in(user_id):
        flash('上班签到成功', 'success')
    else:
        flash('上班签到失败，请稍后重试', 'danger')
    return redirect(url_for('index'))


@app.route('/attendance/sign_out')
@login_required
def attendance_sign_out():
    user_id = session['user']['id']
    if system.sign_out(user_id):
        flash('下班签到成功', 'success')
    else:
        flash('下班签到失败，请稍后重试', 'danger')
    return redirect(url_for('index'))


# 考勤管理路由
@app.route('/attendance/manage')
@login_required
@permission_required('attendance:manage')
def attendance_manage():
    records = system.get_attendance_records()
    return render_template('attendance/manage.html', records=records)


@app.route('/attendance/my_records')
@login_required
def my_attendance_records():
    user_id = session['user']['id']
    records = system.get_attendance_records(user_id)
    return render_template('attendance/my_records.html', records=records)


# # 考勤规则配置路由
# @app.route('/attendance/settings', methods=['GET', 'POST'])
# @login_required
# @permission_required('attendance:manage')
# def attendance_settings():
#     if request.method == 'POST':
#         start_time = request.form['start_time']
#         end_time = request.form['end_time']
#         if system.update_attendance_rules(start_time, end_time):
#             flash('考勤规则更新成功', 'success')
#         else:
#             flash('考勤规则更新失败', 'danger')
#         return redirect(url_for('attendance_settings'))
#
#     # 获取当前规则
#     rules = system.get_attendance_rules()
#     return render_template('attendance/settings.html', rules=rules)


@app.route('/attendance/settings', methods=['GET', 'POST'])
@login_required
@permission_required('attendance:manage')
def attendance_settings():
    # 处理表单提交
    if request.method == 'POST':
        rule_id = request.form.get('rule_id')
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        set_default = 'set_default' in request.form

        if rule_id:
            # 更新现有规则
            if system.update_specific_attendance_rule(rule_id, start_time, end_time, set_default):
                flash('规则更新成功', 'success')
            else:
                flash('规则更新失败', 'danger')
        else:
            # 添加新规则
            if system.update_attendance_rules(start_time, end_time):
                # 如果需要设为默认，额外处理
                if set_default:
                    # 获取刚添加的规则ID
                    with system.connection.cursor() as cursor:
                        cursor.execute("SELECT MAX(id) as max_id FROM attendance_rules")
                        new_rule_id = cursor.fetchone()['max_id']
                        system.set_default_attendance_rule(new_rule_id)
                flash('新规则添加成功', 'success')
            else:
                flash('新规则添加失败', 'danger')
        return redirect(url_for('attendance_settings'))

    # 处理GET请求
    rule_id = request.args.get('rule_id')
    all_rules = system.get_all_attendance_rules()

    # 确定当前要编辑的规则
    if rule_id:
        current_rule = system.get_attendance_rule(rule_id)
        if not current_rule:
            flash('指定的规则不存在', 'danger')
            current_rule = {"work_start_time": "09:00", "work_end_time": "18:00"}
    else:
        # 默认编辑当前默认规则
        default_rule = next((r for r in all_rules if r['is_default']), None)
        current_rule = default_rule or {"work_start_time": "09:00", "work_end_time": "18:00"}

    return render_template('attendance/settings.html',
                           all_rules=all_rules,
                           current_rule=current_rule)


@app.route('/attendance/set-default', methods=['POST'])
@login_required
@permission_required('attendance:manage')
def attendance_set_default():
    data = request.get_json()
    rule_id = data.get('rule_id')

    if system.set_default_attendance_rule(rule_id):
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "设置默认规则失败"})


@app.route('/attendance/delete-rule', methods=['POST'])
@login_required
@permission_required('attendance:manage')
def attendance_delete_rule():
    data = request.get_json()
    rule_id = data.get('rule_id')

    if system.delete_attendance_rule(rule_id):
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "删除规则失败，不能删除最后一条规则"})



if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bootstrap import Bootstrap
import pymysql
from pymysql.cursors import DictCursor  # 关键导入语句
from pymysql import Error
from typing import List, Dict, Optional
import hashlib
import sys

from datetime import datetime, time, timedelta  # 添加time导入

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
                    name VARCHAR(100) NOT NULL,
                    age INT,                          -- 年龄
                    gender ENUM('男', '女', '其他'),  -- 性别
                    education VARCHAR(50),            -- 学历
                    phone VARCHAR(20),                -- 联系电话
                    address TEXT                      -- 现住址
                )
                """)

                # 更新触发器，保持与users表的关联
                cursor.execute("DROP TRIGGER IF EXISTS after_emp_info_insert")
                cursor.execute("""
                CREATE TRIGGER after_emp_info_insert
                AFTER INSERT ON emp_info
                FOR EACH ROW
                BEGIN
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

                # 在原有_initialize_database方法的cursor.execute块中添加以下表结构
                # 招聘职位表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS recruitment_positions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    position_name VARCHAR(100) NOT NULL,  -- 岗位名称
                    salary_range VARCHAR(50) NOT NULL,   -- 薪资范围（如"10k-20k"）
                    hire_count INT NOT NULL,             -- 招聘人数
                    min_education VARCHAR(20) NOT NULL,  -- 最低学历要求
                    is_active TINYINT(1) NOT NULL DEFAULT 1,  -- 是否在招（1=在招，0=撤销）
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP  -- 创建时间
                )
                """)

                cursor.execute("""
                CREATE TABLE IF NOT EXISTS resumes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    candidate_name VARCHAR(100) NOT NULL,
                    age INT,
                    position_id INT NOT NULL,
                    phone VARCHAR(20),
                    email VARCHAR(100),
                    education VARCHAR(50),
                    graduate_school VARCHAR(100),
                    work_experience TEXT,
                    expected_salary VARCHAR(50),
                    resume_file VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status ENUM('active', 'trash') DEFAULT 'active',
                    process_status ENUM('初筛', '面试', '录用', '淘汰') DEFAULT '初筛',  -- 添加这个字段
                    FOREIGN KEY (position_id) REFERENCES recruitment_positions(id)
                )
                """)


                # 面试安排表
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS interviews (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    resume_id INT NOT NULL,              -- 关联简历ID
                    interview_time DATETIME NOT NULL,    -- 面试时间
                    interview_location VARCHAR(200) NOT NULL,  -- 面试地点
                    created_by INT NOT NULL,             -- 安排人ID（员工管理员）
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (resume_id) REFERENCES resumes(id),
                    FOREIGN KEY (created_by) REFERENCES users(id)
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
                    (1014, '管理考勤', 'attendance:manage'),
                    (1015, '发布招聘职位', 'recruitment:create'),
                    (1016, '撤销招聘职位', 'recruitment:cancel'),
                    (1017, '查看简历', 'resume:view'),
                    (1018, '筛选简历', 'resume:filter'),
                    (1019, '安排面试', 'interview:schedule'),
                    (1020, '录用管理', 'recruitment:hire'),
                    (1021, '管理简历', 'resume:manage')
                ]
                cursor.executemany("INSERT INTO permissions (id, name, code) VALUES (%s, %s, %s)", permissions)

                # 插入角色
                roles = [
                    (1001, '系统管理员'),
                    (1002, '普通用户'),
                    (1003, '用户管理员'),
                    (1004, '员工管理员'),
                    (1005, '考勤管理员'),
                    (1006, 'HR')
                ]
                cursor.executemany("INSERT INTO roles (id, name) VALUES (%s, %s)", roles)

                # 插入角色权限关联
                role_permissions = [
                    (1001, 1001), (1001, 1002), (1001, 1003),
                    (1001, 1005), (1001, 1006), (1001, 1007),
                    (1001, 1008), (1001, 1009), (1001, 1010),
                    (1001, 1011), (1001, 1012),(1001, 1004),
                    (1001, 1013), (1001, 1014),(1001, 1015),
                    (1001, 1016), (1001, 1017), (1001, 1018),
                    (1001, 1019), (1001, 1020),(1001, 1021),
                    (1003, 1001), (1003, 1002), (1003, 1004),
                    (1002, 1004), (1002, 1009), (1004, 1008), (1004, 1009), (1004, 1010), (1004, 1011),
                    (1005, 1013), (1005, 1014),
                    # HR拥有招聘管理全部权限
                    (1006, 1015), (1006, 1016), (1006, 1017),
                    (1006, 1018), (1006, 1019), (1006, 1020),(1006, 1021),
                    # HR拥有员工管理全部权限（关联员工管理相关权限）
                    (1006, 1008), (1006, 1009), (1006, 1010), (1006, 1011)
                ]
                cursor.executemany("INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)",
                                   role_permissions)

                # 插入功能
                features = [
                    (1, '用户管理', 'user_management'),
                    (2, '角色管理', 'role_management'),
                    (3, '权限管理', 'permission_management'),
                    (4, '员工管理', 'employee_management')
                    # (5, '考勤管理', 'attendance_management'),
                    # (6, '招聘管理', 'recruitment_management'),
                    # (7, '简历管理','resume_management'),
                    # (8, '面试管理', 'interview_management')
                ]
                cursor.executemany("INSERT INTO features (id, name, code) VALUES (%s, %s, %s)", features)

                # 插入功能权限关联
                feature_permissions = [
                    (1, 1001), (1, 1002), (1, 1003), (1, 1004),
                    (2, 1005), (2, 1006),
                    (3, 1007),
                    (4, 1008), (4, 1009), (4, 1010), (4, 1011),
                    # (5, 1013), (5, 1014),
                    # (6, 1015), (6, 1016),
                    #(7, 1017), (7, 1018),
                    #(8, 1019), (8, 1020)
                ]
                cursor.executemany("INSERT INTO feature_permissions (feature_id, permission_id) VALUES (%s, %s)",
                                   feature_permissions)

                # 插入默认考勤规则
                cursor.execute("""
                    INSERT INTO attendance_rules (work_start_time, work_end_time, is_default)
                    VALUES ('09:00:00', '18:00:00', 1)
                """)

                # 插入用户
                users = [
                    (1001, 'admin', '123456'),
                    (1002, 'user_manager', '123456'),
                    (1003, 'normal_user', '123456'),
                    (1004, 'employee_manager', '123456'),
                    (1005, 'HR', '123456')
                ]
                cursor.executemany("INSERT INTO users (id, username, password) VALUES (%s, %s, %s)", users)

                # 插入用户角色关联
                user_roles = [
                    (1001, 1001),
                    (1002, 1003),
                    (1003, 1002),
                    (1004, 1004),
                    (1005, 1006)
                ]
                cursor.executemany("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", user_roles)

                # 插入测试员工
                employees = [
                    (1006, '张三'),
                    (1007, '李四'),
                    (1008, '王五')
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
    def create_employee(self, name: str, age: int = None, gender: str = None,
                         education: str = None, phone: str = None, address: str = None) -> bool:
        """创建新员工（支持新字段）"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO emp_info (name, age, gender, education, phone, address)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (name, age, gender, education, phone, address))
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

    def update_employee(self, employee_id: int, name: str = None, age: int = None,
                        gender: str = None, education: str = None, phone: str = None,
                        address: str = None) -> bool:
        """更新员工信息（支持新字段）"""
        try:
            # 构建动态更新语句
            update_fields = []
            params = []

            if name is not None:
                update_fields.append("name = %s")
                params.append(name)
            if age is not None:
                update_fields.append("age = %s")
                params.append(age)
            if gender is not None:
                update_fields.append("gender = %s")
                params.append(gender)
            if education is not None:
                update_fields.append("education = %s")
                params.append(education)
            if phone is not None:
                update_fields.append("phone = %s")
                params.append(phone)
            if address is not None:
                update_fields.append("address = %s")
                params.append(address)

            if not update_fields:
                return True  # 没有需要更新的字段

            params.append(employee_id)

            with self.connection.cursor() as cursor:
                cursor.execute(f"""
                    UPDATE emp_info 
                    SET {', '.join(update_fields)} 
                    WHERE id = %s
                """, params)
                affected = cursor.rowcount
            self.connection.commit()
            return affected > 0
        except Error as e:
            print(f"\n✗ 错误: 更新员工信息失败: {e}")
            self.connection.rollback()
            return False

    def get_employee(self, employee_id: int) -> Optional[Dict]:
        """根据ID获取单个员工信息"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM emp_info WHERE id = %s", (employee_id,))
                return cursor.fetchone()
        except Error as e:
            print(f"\n✗ 错误: 获取员工信息失败: {e}")
            return None

    # 考勤规则管理
    # 修改获取考勤规则方法，增强调试
    def get_attendance_rules(self):
        """获取当前考勤规则（修复timedelta类型解析问题）"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, work_start_time, work_end_time, is_default 
                    FROM attendance_rules 
                    WHERE is_default = 1 
                    LIMIT 1
                """)
                rule = cursor.fetchone()

                print(f"查询到的默认规则原始数据: {rule}")
                if rule:
                    print(f"规则ID={rule['id']}, 原始上班时间={rule['work_start_time']} "
                          f"(类型: {type(rule['work_start_time'])})")
                    print(f"规则ID={rule['id']}, 原始下班时间={rule['work_end_time']} "
                          f"(类型: {type(rule['work_end_time'])})")

                if not rule:
                    return {"work_start_time": "09:00", "work_end_time": "18:00"}

                # 修复的时间转换函数，修正timedelta引用
                def format_time(time_value, is_start_time):
                    print(f"转换时间值: {time_value} (类型: {type(time_value)})")

                    # 关键修复：使用正确的timedelta引用（直接使用timedelta，不是datetime.timedelta）
                    if isinstance(time_value, timedelta):
                        # 将秒数转换为小时和分钟
                        total_seconds = int(time_value.total_seconds())
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        result = f"{hours:02d}:{minutes:02d}"
                        print(f"timedelta转换结果: {result}")
                        return result

                    # 处理datetime.time类型
                    elif isinstance(time_value, time):
                        result = time_value.strftime("%H:%M")
                        print(f"time类型转换结果: {result}")
                        return result

                    # 处理字符串类型
                    elif isinstance(time_value, str):
                        for fmt in ['%H:%M:%S', '%H:%M', '%H.%M']:
                            try:
                                dt = datetime.strptime(time_value, fmt)
                                result = dt.strftime("%H:%M")
                                print(f"字符串格式{fmt}转换结果: {result}")
                                return result
                            except ValueError:
                                continue
                        parts = time_value.split(':')
                        if len(parts) >= 2:
                            result = f"{parts[0].zfill(2)}:{parts[1].zfill(2)}"
                            print(f"分割处理结果: {result}")
                            return result

                    # 所有方法失败时返回默认值
                    default = "09:00" if is_start_time else "18:00"
                    print(f"无法解析，返回默认值: {default}")
                    return default

                result = {
                    "id": rule['id'],
                    "work_start_time": format_time(rule['work_start_time'], is_start_time=True),
                    "work_end_time": format_time(rule['work_end_time'], is_start_time=False)
                }
                print(f"格式化后的规则: {result}")
                return result
        except Error as e:
            print(f"\n✗ 错误: 获取考勤规则失败: {e}")
            return {"work_start_time": "09:00", "work_end_time": "18:00"}



    def update_attendance_rules(self, start_time, end_time):
        """更新考勤规则"""
        try:
            with self.connection.cursor() as cursor:
                # 首先将所有规则设为非默认
                cursor.execute("UPDATE attendance_rules SET is_default = 0 WHERE is_default = 1")
                print(f"已将{cursor.rowcount}条规则设为非默认")

                # 修复：使用STR_TO_DATE确保时间正确转换并存储为TIME类型
                cursor.execute("""
                    INSERT INTO attendance_rules (work_start_time, work_end_time, is_default)
                    VALUES (STR_TO_DATE(%s, '%H:%i'), STR_TO_DATE(%s, '%H:%i'), 1)
                """, (start_time, end_time))

                new_rule_id = cursor.lastrowid
                print(f"已插入新的默认规则，ID={new_rule_id}, 时间={start_time}-{end_time}")

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
            work_end = datetime.strptime(rules['work_end_time'], "%H:%M").time()

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
        """获取所有考勤规则，并格式化时间"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT * FROM attendance_rules ORDER BY is_default DESC, id")
                rules = cursor.fetchall()

                # 格式化每条规则的时间
                formatted_rules = []
                for rule in rules:
                    # 处理上班时间
                    if isinstance(rule['work_start_time'], timedelta):
                        total_seconds = int(rule['work_start_time'].total_seconds())
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        rule['work_start_time'] = f"{hours:02d}:{minutes:02d}"

                    # 处理下班时间
                    if isinstance(rule['work_end_time'], timedelta):
                        total_seconds = int(rule['work_end_time'].total_seconds())
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        rule['work_end_time'] = f"{hours:02d}:{minutes:02d}"

                    formatted_rules.append(rule)

                return formatted_rules
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

    # 修改更新特定考勤规则的方法
    def update_specific_attendance_rule(self, rule_id, start_time, end_time, set_default):
        """更新特定的考勤规则"""
        try:
            with self.connection.cursor() as cursor:
                if set_default:
                    # 如果要设为默认，先清除所有默认标记
                    cursor.execute("UPDATE attendance_rules SET is_default = 0")
                    print("已清除所有默认规则标记")

                # 修复：使用STR_TO_DATE转换时间
                cursor.execute("""
                    UPDATE attendance_rules 
                    SET work_start_time = STR_TO_DATE(%s, '%H:%i'), 
                        work_end_time = STR_TO_DATE(%s, '%H:%i'),
                        is_default = %s
                    WHERE id = %s
                """, (start_time, end_time, 1 if set_default else 0, rule_id))

                if cursor.rowcount == 0:
                    print(f"未找到ID为{rule_id}的规则，更新失败")
                    return False

                print(f"已更新规则ID={rule_id}, 时间={start_time}-{end_time}, 是否默认={set_default}")

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

    # 招聘职位管理
    def create_recruitment_position(self, position_name, salary_range, hire_count, min_education):
        """发布招聘职位"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO recruitment_positions 
                    (position_name, salary_range, hire_count, min_education)
                    VALUES (%s, %s, %s, %s)
                """, (position_name, salary_range, hire_count, min_education))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 发布职位失败: {e}")
            self.connection.rollback()
            return False

    def get_recruitment_positions(self, is_active=True):
        """获取招聘职位列表（默认只看在招职位）"""
        try:
            with self.connection.cursor() as cursor:
                if is_active:
                    cursor.execute("""
                        SELECT * FROM recruitment_positions 
                        WHERE is_active = 1 
                        ORDER BY created_at DESC
                    """)
                else:
                    cursor.execute("SELECT * FROM recruitment_positions ORDER BY created_at DESC")
            return cursor.fetchall()
        except Error as e:
            print(f"\n✗ 错误: 获取职位列表失败: {e}")
            return []

    def cancel_recruitment_position(self, position_id):
        """撤销招聘职位"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE recruitment_positions 
                    SET is_active = 0 
                    WHERE id = %s
                """, (position_id,))
                if cursor.rowcount == 0:
                    return False
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 撤销职位失败: {e}")
            self.connection.rollback()
            return False

    # 简历管理
    # def add_resume(self, name, age, education, graduate_school, work_experience,
    #                expected_salary, position_id, contact):
    #     """投递简历（游客/员工管理员）"""
    #     try:
    #         with self.connection.cursor() as cursor:
    #             # 检查职位是否存在且在招
    #             cursor.execute("""
    #                 SELECT id FROM recruitment_positions
    #                 WHERE id = %s AND is_active = 1
    #             """, (position_id,))
    #             if not cursor.fetchone():
    #                 return False
    #
    #             cursor.execute("""
    #                 INSERT INTO resumes
    #                 (name, age, education, graduate_school, work_experience,
    #                  expected_salary, position_id, contact)
    #                 VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    #             """, (name, age, education, graduate_school, work_experience,
    #                   expected_salary, position_id, contact))
    #         self.connection.commit()
    #         return True
    #     except Error as e:
    #         print(f"\n✗ 错误: 投递简历失败: {e}")
    #         self.connection.rollback()
    #         return False

    def add_resume(self, name, age, education, graduate_school, work_experience,
                   expected_salary, position_id, contact):
        """投递简历（包含年龄字段）"""
        try:
            with self.connection.cursor() as cursor:
                # 检查职位是否存在且在招
                cursor.execute("""
                    SELECT id FROM recruitment_positions 
                    WHERE id = %s AND is_active = 1
                """, (position_id,))
                if not cursor.fetchone():
                    print(f"职位验证失败: 职位ID {position_id} 不存在或已关闭")
                    return False

                # 插入语句包含age字段
                cursor.execute("""
                    INSERT INTO resumes 
                    (candidate_name, age, education, graduate_school, work_experience, 
                     expected_salary, position_id, phone, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active')
                """, (name, age, education, graduate_school, work_experience,
                      expected_salary, position_id, contact))
            self.connection.commit()
            print(f"简历提交成功: 姓名 {name}, 年龄 {age}, 职位ID {position_id}")
            return True
        except Error as e:
            print(f"\n✗ 错误: 投递简历数据库操作失败: {e}")
            print(f"提交数据: {name}, {age}, {education}, {position_id}")
            self.connection.rollback()
            return False

    def get_resumes(self, status=None, min_education=None):
        """获取简历列表（支持筛选）"""
        try:
            # 对于pymysql，使用DictCursor来获取字典类型的结果
            cursor = self.connection.cursor(DictCursor)

            # 基础查询，关联职位表获取职位名称
            query = """
            SELECT r.*, p.position_name 
            FROM resumes r
            JOIN recruitment_positions p ON r.position_id = p.id
            WHERE 1=1
            """
            params = []

            # 状态筛选 - 区分流程状态和激活状态
            if status in ['初筛', '面试', '录用', '淘汰']:
                query += " AND r.process_status = %s"  # 使用process_status
                params.append(status)
            # 垃圾桶状态筛选
            elif status == 'trash':
                query += " AND r.status = 'trash'"  # 使用status
            else:
                query += " AND r.status = 'active'"  # 使用status

            # 学历筛选
            if min_education:
                # 定义学历优先级
                education_levels = {'高中': 1, '大专': 2, '本科': 3, '硕士': 4, '博士': 5}
                if min_education in education_levels:
                    min_level = education_levels[min_education]
                    # 筛选出高于等于最低学历的简历
                    query += " AND ("
                    for edu, level in education_levels.items():
                        if level >= min_level:
                            query += " r.education = %s OR"
                            params.append(edu)
                    query = query.rstrip("OR") + ")"

            # 按投递时间倒序排列
            query += " ORDER BY r.created_at DESC"

            cursor.execute(query, params)
            result = cursor.fetchall()
            cursor.close()  # 手动关闭游标
            return result
        except Error as e:
            print(f"获取简历列表失败: {e}")
            return []
    # 面试管理
    def schedule_interview(self, resume_id, interview_time, interview_location, created_by):
        """安排面试"""
        try:
            with self.connection.cursor() as cursor:
                # 更新简历状态为"面试"
                cursor.execute("""
                    UPDATE resumes 
                    SET process_status = '面试' 
                    WHERE id = %s
                """, (resume_id,))

                # 添加面试记录
                cursor.execute("""
                    INSERT INTO interviews 
                    (resume_id, interview_time, interview_location, created_by)
                    VALUES (%s, %s, %s, %s)
                """, (resume_id, interview_time, interview_location, created_by))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 安排面试失败: {e}")
            self.connection.rollback()
            return False

    # 录用管理
    def hire_resume(self, resume_id):
        """录用求职者（自动加入员工表）"""
        try:
            with self.connection.cursor() as cursor:
                # 获取简历信息
                cursor.execute("""
                    SELECT candidate_name FROM resumes WHERE id = %s
                """, (resume_id,))
                resume = cursor.fetchone()
                if not resume:
                    return False

                # 更新简历状态为"录用"
                cursor.execute("""
                    UPDATE resumes 
                    SET process_status = '录用' 
                    WHERE id = %s
                """, (resume_id,))

                # 加入员工表（自动触发users表插入）
                cursor.execute("""
                    INSERT INTO emp_info (name) VALUES (%s)
                """, (resume['candidate_name'],))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 录用失败: {e}")
            self.connection.rollback()
            return False

    def move_resume_to_trash(self, resume_id):
        """将简历移到垃圾桶"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE resumes 
                    SET status = 'trash' 
                    WHERE id = %s
                """, (resume_id,))
                self.connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            self.connection.rollback()
            print(f"移动简历到垃圾桶失败: {e}")
            return False

    def restore_resume(self, resume_id):
        """从垃圾桶恢复简历"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE resumes 
                    SET status = 'active' 
                    WHERE id = %s
                """, (resume_id,))
                self.connection.commit()
                return cursor.rowcount > 0
        except Exception as e:
            self.connection.rollback()
            print(f"恢复简历失败: {e}")
            return False

    # 在PermissionSystem类中添加获取单个简历的方法
    def get_resume_by_id(self, resume_id):
        """根据ID获取单个简历详情"""
        try:
            cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute("""
                SELECT r.*, p.position_name 
                FROM resumes r
                JOIN recruitment_positions p ON r.position_id = p.id
                WHERE r.id = %s
            """, (resume_id,))
            resume = cursor.fetchone()
            cursor.close()
            return resume
        except pymysql.MySQLError as e:
            print(f"获取简历详情失败: {e}")
            return None

    def reject_resume(self, resume_id):
        """淘汰求职者"""
        try:
            with self.connection.cursor() as cursor:
                # 更新简历状态为"淘汰"
                cursor.execute("""
                    UPDATE resumes 
                    SET process_status = '淘汰' 
                    WHERE id = %s
                """, (resume_id,))
            self.connection.commit()
            return True
        except Error as e:
            print(f"\n✗ 错误: 淘汰失败: {e}")
            self.connection.rollback()
            return False

    # 在PermissionSystem类中添加清空垃圾桶的方法
    def clear_resume_trash(self):
        """永久删除垃圾桶中的所有简历"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("DELETE FROM resumes WHERE status = 'trash'")
                self.connection.commit()
                return cursor.rowcount  # 返回删除的记录数
        except Error as e:
            print(f"清空简历垃圾桶失败: {e}")
            self.connection.rollback()
            return 0

    def delete_resume_permanently(self, resume_id):
        """从数据库中永久删除简历"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("DELETE FROM resumes WHERE id = %s", (resume_id,))
                self.connection.commit()
                return cursor.rowcount > 0
        except Error as e:
            print(f"永久删除简历失败: {e}")
            self.connection.rollback()
            return False








#################################################################
#################################################################


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
        # 获取当前用户的考勤记录
        user_id = session['user']['id']
        attendance_records = system.get_attendance_records(user_id)

        # 获取考勤规则
        attendance_rules = system.get_attendance_rules()

        # 引入datetime供模板使用
        from datetime import datetime

        return render_template(
            'index.html',
            user=session['user'],
            attendance_records=attendance_records,
            attendance_rules=attendance_rules,
            datetime=datetime
        )
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


@app.route('/employees/detail/<int:employee_id>')
@login_required
@permission_required('employees:view')
def employee_detail(employee_id):
    """查看员工详细信息"""
    employee = system.get_employee(employee_id)
    if not employee:
        flash('员工不存在', 'danger')
        return redirect(url_for('list_employees'))

    # 获取该员工的用户信息（如果存在）
    user_info = None
    roles = []  # 存储员工角色
    try:
        with system.connection.cursor() as cursor:
            # 获取用户信息
            cursor.execute("SELECT * FROM users WHERE id = %s", (employee_id,))
            user_info = cursor.fetchone()

            # 获取用户角色（通过用户ID关联角色表）
            if user_info:
                cursor.execute("""
                    SELECT r.name FROM roles r
                    JOIN user_roles ur ON r.id = ur.role_id
                    WHERE ur.user_id = %s
                """, (employee_id,))
                roles = [row['name'] for row in cursor.fetchall()]

    except Error as e:
        print(f"\n✗ 错误: 获取员工用户信息失败: {e}")

    # 获取该员工的考勤记录
    attendance_records = system.get_attendance_records(employee_id)

    return render_template('employees/detail.html',
                           employee=employee,
                           user_info=user_info,
                           roles=roles,
                           attendance_records=attendance_records)


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
        # 获取表单数据
        name = request.form['name']
        age = request.form['age'] if request.form['age'] else None
        gender = request.form['gender'] if request.form['gender'] else None
        education = request.form['education'] if request.form['education'] else None
        phone = request.form['phone'] if request.form['phone'] else None
        address = request.form['address'] if request.form['address'] else None

        # 转换年龄为整数
        if age:
            try:
                age = int(age)
            except ValueError:
                age = None

        if system.create_employee(name, age, gender, education, phone, address):
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
    # 获取当前员工信息
    employee = system.get_employee(employee_id)
    if not employee:
        flash('员工不存在', 'danger')
        return redirect(url_for('list_employees'))

    if request.method == 'POST':
        # 获取表单数据
        name = request.form['name']
        age = request.form['age'] if request.form['age'] else None
        gender = request.form['gender'] if request.form['gender'] else None
        education = request.form['education'] if request.form['education'] else None
        phone = request.form['phone'] if request.form['phone'] else None
        address = request.form['address'] if request.form['address'] else None

        # 转换年龄为整数
        if age:
            try:
                age = int(age)
            except ValueError:
                age = None

        if system.update_employee(employee_id, name, age, gender, education, phone, address):
            flash('员工信息更新成功', 'success')
            return redirect(url_for('employee_detail', employee_id=employee_id))
        else:
            flash('员工信息更新失败', 'danger')

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
#     # 处理表单提交
#     if request.method == 'POST':
#         rule_id = request.form.get('rule_id')
#         start_time = request.form['start_time']
#         end_time = request.form['end_time']
#         set_default = 'set_default' in request.form
#
#         if rule_id:
#             # 更新现有规则
#             if system.update_specific_attendance_rule(rule_id, start_time, end_time, set_default):
#                 flash('规则更新成功', 'success')
#             else:
#                 flash('规则更新失败', 'danger')
#         else:
#             # 添加新规则
#             if system.update_attendance_rules(start_time, end_time):
#                 # 如果需要设为默认，额外处理
#                 if set_default:
#                     # 获取刚添加的规则ID
#                     with system.connection.cursor() as cursor:
#                         cursor.execute("SELECT MAX(id) as max_id FROM attendance_rules")
#                         new_rule_id = cursor.fetchone()['max_id']
#                         system.set_default_attendance_rule(new_rule_id)
#                 flash('新规则添加成功', 'success')
#             else:
#                 flash('新规则添加失败', 'danger')
#         return redirect(url_for('attendance_settings'))
#
#     # 处理GET请求
#     rule_id = request.args.get('rule_id')
#     all_rules = system.get_all_attendance_rules()
#
#     # 确定当前要编辑的规则
#     if rule_id:
#         current_rule = system.get_attendance_rule(rule_id)
#         if not current_rule:
#             flash('指定的规则不存在', 'danger')
#             current_rule = {"work_start_time": "09:00", "work_end_time": "18:00"}
#     else:
#         # 默认编辑当前默认规则
#         default_rule = next((r for r in all_rules if r['is_default']), None)
#         current_rule = default_rule or {"work_start_time": "09:00", "work_end_time": "18:00"}
#
#     return render_template('attendance/settings.html',
#                            all_rules=all_rules,
#                            current_rule=current_rule)


# 1. 修复考勤规则设置路由中的新增规则逻辑
@app.route('/attendance/settings', methods=['GET', 'POST'])
@login_required
@permission_required('attendance:manage')
def attendance_settings():
    # 处理表单提交
    if request.method == 'POST':
        rule_id = request.form.get('rule_id', '').strip()  # 确保空值处理正确
        start_time = request.form.get('start_time', '').strip()
        end_time = request.form.get('end_time', '').strip()
        set_default = 'set_default' in request.form

        # 验证时间格式
        try:
            # 检查时间格式是否正确
            datetime.strptime(start_time, "%H:%M")
            datetime.strptime(end_time, "%H:%M")
        except ValueError:
            flash('时间格式错误，请使用HH:MM格式', 'danger')
            return redirect(url_for('attendance_settings'))

        if rule_id:
            # 更新现有规则
            if system.update_specific_attendance_rule(rule_id, start_time, end_time, set_default):
                flash('规则更新成功', 'success')
            else:
                flash('规则更新失败', 'danger')
        else:
            # 添加新规则 - 修复逻辑
            if system.update_attendance_rules(start_time, end_time):
                # 如果需要设为默认，额外处理
                if set_default:
                    # 获取刚添加的规则ID
                    try:
                        with system.connection.cursor() as cursor:
                            cursor.execute("SELECT MAX(id) as max_id FROM attendance_rules")
                            result = cursor.fetchone()
                            if result and result['max_id']:
                                new_rule_id = result['max_id']
                                system.set_default_attendance_rule(new_rule_id)
                            else:
                                flash('新规则添加成功，但设置默认规则失败', 'warning')
                    except Error as e:
                        print(f"设置默认规则失败: {e}")
                        flash('新规则添加成功，但设置默认规则失败', 'warning')
                flash('新规则添加成功', 'success')
            else:
                flash('新规则添加失败', 'danger')
        return redirect(url_for('attendance_settings'))

    # 处理GET请求
    rule_id = request.args.get('rule_id')
    all_rules = system.get_all_attendance_rules()

    # 格式化所有规则的时间显示
    formatted_rules = []
    for rule in all_rules:
        # 处理上班时间
        if isinstance(rule['work_start_time'], timedelta):
            total_seconds = int(rule['work_start_time'].total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            rule['work_start_time'] = f"{hours:02d}:{minutes:02d}"

        # 处理下班时间
        if isinstance(rule['work_end_time'], timedelta):
            total_seconds = int(rule['work_end_time'].total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            rule['work_end_time'] = f"{hours:02d}:{minutes:02d}"

        formatted_rules.append(rule)

    # 确定当前要编辑的规则
    current_rule = {"work_start_time": "09:00", "work_end_time": "18:00", "id": None, "is_default": False}
    if rule_id:
        current_rule = system.get_attendance_rule(rule_id)
        if not current_rule:
            flash('指定的规则不存在', 'danger')
    else:
        # 默认编辑当前默认规则
        default_rule = next((r for r in formatted_rules if r['is_default']), None)
        if default_rule:
            current_rule = default_rule

    return render_template('attendance/settings.html',
                           all_rules=formatted_rules,
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


# 游客登录相关
@app.route('/login/guest')
def guest_login():
    """游客登录"""
    session['user'] = {
        'id': 0,
        'username': 'guest',
        'is_guest': True
    }
    flash('游客登录成功', 'success')
    return redirect(url_for('company_intro'))


@app.route('/company')
def company_intro():
    """公司介绍页面（游客可见）"""
    return render_template('guest/company.html')


# 招聘职位相关（游客和员工管理员可见）
@app.route('/recruitment/positions')
def list_positions():
    """查看招聘职位"""
    positions = system.get_recruitment_positions()
    return render_template('recruitment/positions.html', positions=positions)


# 简历投递（游客功能）
# @app.route('/recruitment/resumes/create', methods=['GET', 'POST'])
# def create_resume():
#     """投递简历"""
#     if request.method == 'POST':
#         # 表单数据获取
#         data = {
#             'name': request.form['name'],
#             'age': request.form['age'],
#             'education': request.form['education'],
#             'graduate_school': request.form['graduate_school'],
#             'work_experience': request.form['work_experience'],
#             'expected_salary': request.form['expected_salary'],
#             'position_id': request.form['position_id'],
#             'contact': request.form['contact']
#         }
#
#         if system.add_resume(**data):
#             flash('简历投递成功', 'success')
#             return redirect(url_for('list_positions'))
#         else:
#             flash('简历投递失败（职位可能已关闭）', 'danger')
#
#     # 获取在招职位
#     positions = system.get_recruitment_positions()
#     return render_template('recruitment/resume_create.html', positions=positions)


@app.route('/recruitment/resumes/create', methods=['GET', 'POST'])
def create_resume():
    """投递简历（包含年龄验证）"""
    if request.method == 'POST':
        # 获取表单数据
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '').strip()  # 获取年龄字段
        education = request.form.get('education', '').strip()
        graduate_school = request.form.get('graduate_school', '').strip()
        work_experience = request.form.get('work_experience', '').strip()
        expected_salary = request.form.get('expected_salary', '').strip()
        position_id = request.form.get('position_id', '').strip()
        contact = request.form.get('contact', '').strip()

        # 详细数据验证
        errors = []

        # 验证年龄（允许为空或有效数字）
        age_val = None
        if age:
            try:
                age_val = int(age)
                if age_val < 18 or age_val > 60:
                    errors.append("年龄必须在18-60岁之间")
            except ValueError:
                errors.append("年龄必须是有效的数字")

        # 其他字段验证保持不变
        # ...

        # 如果有验证错误，显示错误信息
        if errors:
            for error in errors:
                flash(error, 'danger')
            positions = system.get_recruitment_positions()
            return render_template('recruitment/resume_create.html', positions=positions)

        # 准备提交数据
        data = {
            'name': name,
            'age': age_val,  # 可能为None（允许为空）
            'education': education,
            'graduate_school': graduate_school,
            'work_experience': int(work_experience),
            'expected_salary': expected_salary,
            'position_id': int(position_id),
            'contact': contact
        }

        # 尝试提交简历
        try:
            if system.add_resume(**data):
                flash('简历投递成功', 'success')
                return redirect(url_for('list_positions'))
            else:
                flash('简历提交失败，请稍后重试', 'danger')
        except Exception as e:
            flash(f'提交失败: {str(e)}', 'danger')
            print(f'简历提交数据库错误: {str(e)}')

    # 获取在招职位
    positions = system.get_recruitment_positions()
    return render_template('recruitment/resume_create.html', positions=positions)


# 员工管理员招聘管理
# 招聘职位管理路由（修复版）
# @app.route('/recruitment/admin/positions', methods=['GET', 'POST'])
# @login_required
# @permission_required('recruitment:create')  # 确保使用正确的权限代码
# def manage_positions():
#     # 处理发布新职位的表单提交
#     if request.method == 'POST':
#         try:
#             # 获取表单数据
#             position_name = request.form.get('position_name')
#             salary_range = request.form.get('salary_range')
#             hire_count = int(request.form.get('hire_count', 0))
#             min_education = request.form.get('min_education')
#
#             # 验证表单数据
#             if not all([position_name, salary_range, hire_count > 0, min_education]):
#                 flash('请填写完整的职位信息', 'danger')
#                 return redirect(url_for('manage_positions'))
#
#             # 调用系统方法创建职位
#             success = system.create_recruitment_position(
#                 position_name=position_name,
#                 salary_range=salary_range,
#                 hire_count=hire_count,
#                 min_education=min_education
#             )
#
#             if success:
#                 flash('职位发布成功', 'success')
#             else:
#                 flash('职位发布失败，请重试', 'danger')
#
#         except Exception as e:
#             flash(f'发布职位时发生错误: {str(e)}', 'danger')
#             app.logger.error(f'职位发布错误: {str(e)}')
#
#         return redirect(url_for('manage_positions'))
#
#     # 处理GET请求，显示职位列表
#     # positions = system.get_all_recruitment_positions()
#     positions = system.get_recruitment_positions(is_active=False)
#     return render_template('recruitment/admin/positions_manage.html', positions=positions)

@app.route('/recruitment/admin/positions', methods=['GET', 'POST'])
@login_required
@permission_required('recruitment:create')
def manage_positions():
    if request.method == 'POST':
        try:
            # 获取表单数据，提供默认值避免None
            position_name = request.form.get('position_name', '').strip()
            salary_range = request.form.get('salary_range', '').strip()
            hire_count = request.form.get('hire_count', 0)
            min_education = request.form.get('min_education', '').strip()

            # 转换招聘人数为整数（处理可能的转换错误）
            try:
                hire_count = int(hire_count)
            except ValueError:
                hire_count = 0

            # 更合理的表单验证
            errors = []
            if not position_name:
                errors.append('请输入职位名称')
            if not salary_range:
                errors.append('请输入薪资范围')
            if hire_count <= 0:
                errors.append('招聘人数必须大于0')
            if not min_education:
                errors.append('请选择最低学历要求')

            if errors:
                for error in errors:
                    flash(error, 'danger')
                return redirect(url_for('manage_positions'))

            # 调用系统方法创建职位
            success = system.create_recruitment_position(
                position_name=position_name,
                salary_range=salary_range,
                hire_count=hire_count,
                min_education=min_education
            )

            if success:
                flash('职位发布成功', 'success')
            else:
                flash('职位发布失败，请重试', 'danger')

        except Exception as e:
            flash(f'发布职位时发生错误: {str(e)}', 'danger')
            app.logger.error(f'职位发布错误: {str(e)}')

        return redirect(url_for('manage_positions'))

    # 获取所有职位（包括已撤销的）
    positions = system.get_recruitment_positions(is_active=False)
    return render_template('recruitment/admin/positions_manage.html', positions=positions)



@app.route('/recruitment/admin/positions/cancel/<int:position_id>')
@login_required
@permission_required('recruitment:cancel')  # 新增权限控制
def cancel_position(position_id):
    """撤销招聘职位"""
    if system.cancel_recruitment_position(position_id):
        flash('职位已撤销', 'success')
    else:
        flash('撤销失败', 'danger')
    return redirect(url_for('manage_positions'))


# 简历管理（员工管理员功能）
@app.route('/recruitment/admin/resumes')
@login_required
@permission_required('resume:view')  # 新增权限控制
def manage_resumes():
    """筛选/查看简历"""
    status = request.args.get('status')
    min_education = request.args.get('min_education')
    resumes = system.get_resumes(status=status, min_education=min_education)
    return render_template('recruitment/admin/resumes_manage.html', resumes=resumes)


# 面试安排
@app.route('/recruitment/admin/interview/<int:resume_id>', methods=['GET', 'POST'])
@login_required
@permission_required('interview:schedule')  # 新增权限控制
def schedule_interview(resume_id):
    """安排面试"""
    if request.method == 'POST':
        if system.schedule_interview(
                resume_id=resume_id,
                interview_time=request.form['interview_time'],
                interview_location=request.form['interview_location'],
                created_by=session['user']['id']
        ):
            flash('面试安排成功', 'success')
            return redirect(url_for('manage_resumes'))

    return render_template('recruitment/admin/interview.html', resume_id=resume_id)


# 录用操作
@app.route('/recruitment/admin/hire/<int:resume_id>')
@login_required
@permission_required('recruitment:hire')  # 新增权限控制
def hire_candidate(resume_id):
    """录用求职者"""
    if system.hire_resume(resume_id):
        flash('录用成功，已加入员工表', 'success')
    else:
        flash('录用失败', 'danger')
    return redirect(url_for('manage_resumes'))


@app.route('/recruitment/resumes/trash/<int:resume_id>', methods=['POST'])
@login_required
@permission_required('resume:manage')
def trash_resume(resume_id):
    """将简历移到垃圾桶"""
    if system.move_resume_to_trash(resume_id):
        flash('简历已移至垃圾桶', 'success')
    else:
        flash('操作失败，请重试', 'danger')
    return redirect(url_for('manage_resumes'))

@app.route('/recruitment/resumes/restore/<int:resume_id>', methods=['POST'])
@login_required
@permission_required('resume:manage')
def restore_resume(resume_id):
    """从垃圾桶恢复简历"""
    if system.restore_resume(resume_id):
        flash('简历已恢复', 'success')
    else:
        flash('操作失败，请重试', 'danger')
    return redirect(url_for('manage_resumes_trash'))

@app.route('/recruitment/resumes/trash')
@login_required
@permission_required('resume:manage')
def manage_resumes_trash():
    """查看垃圾桶中的简历"""
    resumes = system.get_resumes(status='trash')
    return render_template('recruitment/admin/resumes_trash.html',
                          resumes=resumes,
                          title="简历垃圾桶")

    # 添加查看简历详情的路由
@app.route('/recruitment/resumes/<int:resume_id>')
@login_required
def view_resume(resume_id):
    """查看简历详情"""
    resume = system.get_resume_by_id(resume_id)
    if not resume:
        flash('未找到该简历', 'danger')
        return redirect(url_for('manage_resumes'))

    return render_template('recruitment/admin/resume_view.html',
                           resume=resume)

@app.route('/recruitment/admin/reject/<int:resume_id>')
@login_required
@permission_required('recruitment:hire')  # 使用与录用相同的权限
def reject_candidate(resume_id):
    """淘汰求职者"""
    if system.reject_resume(resume_id):
        flash('已将该候选人标记为淘汰', 'success')
    else:
        flash('操作失败', 'danger')
    return redirect(url_for('manage_resumes'))


    # 添加清空垃圾桶的路由
@app.route('/recruitment/resumes/trash/clear', methods=['POST'])
@login_required
@permission_required('resume:manage')
def clear_resume_trash():
    """清空简历垃圾桶"""
    deleted_count = system.clear_resume_trash()
    if deleted_count > 0:
        flash(f'成功清空垃圾桶，共删除 {deleted_count} 份简历', 'success')
    else:
        flash('垃圾桶为空或清空失败', 'info')
    return redirect(url_for('manage_resumes_trash'))


# 添加彻底删除简历的路由
@app.route('/recruitment/resumes/delete/<int:resume_id>', methods=['POST'])
@login_required
@permission_required('resume:manage')
def delete_resume(resume_id):
    """永久删除简历"""
    if system.delete_resume_permanently(resume_id):
        flash('简历已永久删除', 'success')
    else:
        flash('删除失败，请重试', 'danger')
    return redirect(url_for('manage_resumes_trash'))


if __name__ == '__main__':
    app.run(debug=True)

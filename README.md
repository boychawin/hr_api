# hr_api

###  1.ให้ทำ Api ระบบ hr โดยสามารถ เพิ่ม ลบ แก้ไข ดู ข้อมูลพนักงาน
#####  - มีการ authentication สำหรับ admin ที่สามารถยิง api ทุกเส้นได้โดยใช้ token และ refresh token หลังจาก login เข้าสู่ระบบ

### 2. ทำฟังชั่นรับ parameter 2 ตัว เป็น array ทั้งคู่ โดยรีเทินค่า 2 ค่า
##### - ใช้ for i เท่านั้น
##### - ค่าที่ต้องรีเทิร์น 1. array ที่รวมข้อมูลโดยไม่มีข้อมูลซ้ำ 2. array ที่รวมข้อมูลที่รับเข้าด้วยกันโดยตัดข้อมูลซ้ำ
##### เช่น  รับค่า [a,b,c] [b,c,d] ต้องรีเทิร์น [a,b,c,d] [a,d]

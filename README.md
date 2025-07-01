# BTL.ATBMTT

![image](https://github.com/user-attachments/assets/74a9f47f-6188-46f0-98d3-abe2bf4f04a8)
![image](https://github.com/user-attachments/assets/657a66ae-589b-4bf0-b7dd-bb07e3338f59)
![image](https://github.com/user-attachments/assets/12d296cd-8376-4b47-bab2-e956a4bb5271)
![image](https://github.com/user-attachments/assets/c3632626-55a9-4e67-aa95-d9251c5c71c4)
I. Tổng quan về trò chơi

"Giải mã Kho báu" là một trò chơi giải đố, nơi người chơi phải giải mã các thông điệp được mã hóa bằng nhiều thuật toán mật mã khác nhau để tiến bộ qua các cấp độ và kiếm điểm. Mục tiêu là giải mã thành công tất cả các thông điệp để tìm ra kho báu cuối cùng (hoặc đạt cấp độ cao nhất).

II. Cách chơi

Đăng ký/Đăng nhập:

Khi truy cập trò chơi, bạn sẽ có tùy chọn để đăng ký tài khoản mới hoặc đăng nhập bằng tài khoản hiện có.

Đăng ký yêu cầu một tên người dùng và mật khẩu.

Đăng nhập sẽ đưa bạn đến cấp độ hiện tại của mình.

Các cấp độ:

Trò chơi được chia thành nhiều cấp độ. Mỗi cấp độ sẽ có một thông điệp được mã hóa khác nhau và sử dụng một thuật toán mã hóa cụ thể hoặc kết hợp các thuật toán.

Khi bạn giải mã thành công một thông điệp, bạn sẽ được thưởng điểm và chuyển sang cấp độ tiếp theo.

Giải mã thông điệp:

Tại mỗi cấp độ, bạn sẽ thấy một thông điệp đã được mã hóa.

Bạn cần xác định thuật toán mã hóa đã được sử dụng và nhập câu trả lời đã giải mã vào ô nhập liệu.

Đối với các mật mã cần khóa (ví dụ: Vigenere, AES, RSA), trò chơi sẽ cung cấp khóa công khai hoặc các gợi ý liên quan đến khóa nếu cần.

Thử thách:

Bạn có giới hạn số lần thử (5 lần) cho mỗi cấp độ.

Nếu bạn giải mã không chính xác, số lần thử của bạn sẽ giảm.

Nếu hết số lần thử, bạn sẽ phải bắt đầu lại cấp độ đó.

Kiếm điểm:

Giải mã thành công một thông điệp sẽ giúp bạn kiếm được điểm. Số điểm kiếm được có thể khác nhau tùy theo độ khó của cấp độ.

Mục tiêu là tích lũy càng nhiều điểm càng tốt.

Theo dõi tiến độ:

Giao diện người dùng sẽ hiển thị cấp độ hiện tại của bạn, số điểm bạn đã kiếm được và số lần thử còn lại cho cấp độ hiện tại.

III. Các chức năng chính

Hệ thống người dùng (Đăng ký/Đăng nhập):

Quản lý tài khoản người chơi.

Lưu trữ thông tin người dùng (tên người dùng, mật khẩu đã mã hóa).

Duy trì trạng thái phiên đăng nhập.

Quản lý cấp độ và điểm số:

Theo dõi cấp độ hiện tại của mỗi người chơi.

Cập nhật điểm số của người chơi dựa trên các lần giải mã thành công.

Xác định thông điệp mã hóa và thuật toán cho mỗi cấp độ.

Đặt số lần thử cho mỗi cấp độ và reset khi thành công.

Các thuật toán mã hóa/giải mã được sử dụng:
Dựa trên mã, trò chơi sử dụng các thuật toán mật mã sau (có thể có nhiều hơn khi phát triển):

Caesar Cipher:

Mã hóa/giải mã bằng cách dịch chuyển các chữ cái trong bảng chữ cái một số vị trí cố định.

Bạn sẽ cần xác định "shift" (số lượng dịch chuyển).

Vigenère Cipher:

Mã hóa/giải mã bằng cách sử dụng một từ khóa để dịch chuyển các chữ cái khác nhau.

Bạn sẽ cần xác định "key" (từ khóa).

RSA (Rivest–Shamir–Adleman):

Mã hóa/giải mã bất đối xứng sử dụng một cặp khóa (khóa công khai và khóa riêng tư).

Trong trò chơi, bạn có thể được cung cấp khóa công khai để mã hóa hoặc cần giải mã bằng khóa riêng tư (được quản lý bởi máy chủ).

AES (Advanced Encryption Standard):

Mã hóa/giải mã đối xứng sử dụng cùng một khóa cho cả mã hóa và giải mã.

Bạn sẽ cần xác định "key" (khóa bí mật).

API Backend (Flask):

/register: Đăng ký người dùng mới.

/login: Đăng nhập người dùng hiện có.

/logout: Đăng xuất người dùng.

/get_level_data: Lấy thông tin cấp độ hiện tại cho người dùng đã đăng nhập (thông điệp mã hóa, loại mật mã, gợi ý nếu có).

/decode: Gửi câu trả lời giải mã của người chơi để kiểm tra. Xử lý logic điểm số và chuyển cấp.

/: Render giao diện chính của trò chơi (file index.html).

Giao diện người dùng (HTML/CSS/JavaScript):

Hiển thị thông tin cấp độ, thông điệp mã hóa, điểm số và số lần thử còn lại.

Cho phép người chơi nhập câu trả lời giải mã.

Cung cấp các nút tương tác (ví dụ: nút gửi, nút đăng xuất).

Sử dụng Bootstrap cho giao diện responsive.

Có các hàm JavaScript mô phỏng giải mã Caesar và Vigenere (mặc dù việc giải mã thực tế sẽ được xử lý ở backend để đảm bảo tính toàn vẹn và bảo mật).

IV. Các tệp quan trọng và vai trò của chúng:

app1.py (hoặc app.py nếu được cấu hình là tệp chính): Đây là tệp chính của ứng dụng Flask, chứa các định tuyến API, logic xử lý người dùng, quản lý cấp độ, điểm số và tích hợp với cơ sở dữ liệu. Nó cũng chịu trách nhiệm tạo và quản lý các khóa mã hóa.

cipher_utils.py: Chứa các hàm Python riêng biệt cho từng thuật toán mã hóa và giải mã (Caesar, Vigenere, RSA, AES). Điều này giúp tổ chức mã tốt hơn và dễ dàng tái sử dụng.

index.html: Giao diện người dùng frontend của trò chơi. Nó chứa HTML cho cấu trúc, CSS cho phong cách và JavaScript để xử lý tương tác người dùng, hiển thị thông tin và gửi yêu cầu đến backend.

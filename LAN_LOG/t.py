from flask import Flask, send_from_directory

app = Flask(__name__)

@app.route('/images/<path:filename>')
def get_image(filename):
    # 从指定目录中发送文件
    return send_from_directory('static/', filename)

if __name__ == '__main__':
    app.run()

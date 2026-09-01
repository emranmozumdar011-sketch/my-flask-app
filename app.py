import os
import shutil
from flask import Flask, render_template, request, send_file, jsonify
import yt_dlp

app = Flask(__name__)

DOWNLOAD_FOLDER = 'downloads'
if not os.path.exists(DOWNLOAD_FOLDER):
    os.makedirs(DOWNLOAD_FOLDER)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download', methods=['GET'])
def download_video():
    video_url = request.args.get('url')
    
    if not video_url:
        return jsonify({'error': 'No URL provided'}), 400

    job_id = str(os.urandom(4).hex())
    output_template = os.path.join(DOWNLOAD_FOLDER, f'video_{job_id}.%(ext)s')

    ydl_opts = {
        'format': 'best',
        'outtmpl': output_template,
        'quiet': True,
        'extractor_args': {
            'youtube': {
                'player_client': ['android', 'web']
            }
        },
        'http_headers': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
        }
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info_dict = ydl.extract_info(video_url, download=True)
            filename = ydl.prepare_filename(info_dict)

        def generate():
            with open(filename, 'rb') as f:
                yield from f
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception as e:
                print(f"Cleanup error: {e}")

        return app.response_class(
            generate(),
            mimetype='video/mp4',
            headers={
                "Content-Disposition": f"attachment; filename=EM_Fast_4K_Video.mp4"
            }
        )

    except Exception as e:
        try:
            shutil.rmtree(DOWNLOAD_FOLDER, ignore_errors=True)
            os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
        except:
            pass
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

from flask import Flask, request, send_file, after_this_request
import yt_dlp
import os

app = Flask(__name__)

@app.route('/download')
def download_video():
    url = request.args.get('url')
    if not url:
        return "No URL provided", 400
    
    output_path = 'downloaded_video.mp4'
    
    if os.path.exists(output_path):
        os.remove(output_path)

    ydl_opts = {
        'outtmpl': output_path,
        'format': 'best',
        'noplaylist': True
    }
    
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])
        
        @after_this_request
        def remove_file(response):
            try:
                if os.path.exists(output_path):
                    os.remove(output_path)
            except Exception:
                pass
            return response

        return send_file(output_path, as_attachment=True, download_name='em_video_4k.mp4')
        
    except Exception as e:
        return f"Download failed: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

"""Local interactive demonstration. No network or HTTP service is started."""
import argparse
import sys
from .detector import Detector
from .pipeline import LocalSession


def main():
    parser = argparse.ArgumentParser(description='로컬 개인정보 가명화: 텍스트를 표준 입력으로 받습니다.')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--model-dir', help='사전 준비된 로컬 AEGIS 모델 디렉터리')
    mode.add_argument('--rules-only', action='store_true', help='전화번호·이메일만 검사 (불완전)')
    args = parser.parse_args()
    try:
        detector = Detector(args.model_dir)
        with LocalSession(detector) as session:
            result = session.process(sys.stdin.read())
        print('검사 범위:', result.coverage)
        print('탐지 유형:', ', '.join(result.detection_types) or '없음')
        print('재검사 탐지 건수:', len(result.remaining))
        for item in result.remaining:
            print(f"  - {item['type']}: 위치 {item['start']}–{item['end']}")
        print('탐지 누락 가능성이 있으므로 전송 전 확인하세요.')
        print('가명화 결과:')
        print(result.text, end='')
    except Exception:
        # Exceptions can contain request text; do not include their details.
        print('검사 실패: 모델 설정이나 입력 상태를 확인하세요. 검사 완료가 아닙니다.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

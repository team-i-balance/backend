"""어절 단위로 자르되 뒤에 붙은 조사·어미만 떼어내는 분리기.

mecab 형태소 분리는 '1,240억' 을 5조각, '영업이익' 을 2조각으로 잘라 구간 폭이 커지고,
공백 분리는 '블루웨일이' 처럼 조사가 붙어 정답 구간 경계와 안 맞는다. 그 중간.
"""
import re

import mecab

WORD = re.compile(r"\w+(?:[-_]\w+)*|\S")
HANGUL = re.compile(r"[가-힣]")
# 어절 끝에서 떼어낼 품사: 조사, 어미, 서술격 조사 '이(다)', '하다'류 접미사·보조용언
TAIL = ("J", "E", "VCP", "XSV", "XSA", "VX")
# mecab 이 모르는 고유명사 뒤의 조사는 명사로 잘못 붙는다 ('지오신호연구소와의' → ... '와의'/NNG).
# 마지막 형태소 글자가 흔한 조사와 똑같으면 조사로 본다
JOSA = {"의", "와의", "과의", "와", "과", "로", "으로", "가", "이", "은", "는", "을", "를", "에", "에서", "에게",
        "도", "만", "랑", "이랑", "까지", "부터", "처럼", "보다"}


class EojeolSplitter:
    def __init__(self):
        self.tagger = mecab.MeCab()

    def split_word(self, w):
        """'블루웨일이' → ['블루웨일', '이']. 떼어낼 게 없으면 [w]."""
        if not HANGUL.search(w):
            return [w]
        cut = len(w)
        for m in reversed(self.tagger.parse(w)):
            tags = m.feature.pos.split("+")
            if not all(t.startswith(TAIL) for t in tags) and not (cut == len(w) and m.surface in JOSA):
                break
            st = m.span[0]
            if st <= 0:
                break
            cut = st
        return [w] if cut >= len(w) else [w[:cut], w[cut:]]

    def __call__(self, text):
        for m in WORD.finditer(text):
            pos = m.start()
            for piece in self.split_word(m.group()):
                yield piece, pos, pos + len(piece)
                pos += len(piece)

from collections import Counter
import re


alphabet = "abcdefghijklmnopqrstuvwxyz"
eng_freq = [.0817, .0149, .0278, .0425, .1270, .0223, .0202, .0609, .0697, .0015, .0077, .0403, .0241, .0675, .0751,
            .0193, .0010, .0599, .0633, .0906, .0276, .0098, .0236, .0015, .0197, .0007]

###################     Kasiski Test    #########################
def find_segments(segmentlen, ciphertext):
    length = len(ciphertext)
    dict = {}
    for i in range(0, length - segmentlen, 1):
        segment = ciphertext[i:i+segmentlen]
        if segment in dict:
            dict[segment] = dict.get(segment) + 1
        else: 
            dict[segment] = 1
    return dict

def filter_segments(segments):
    """ Removes segments from dictionary with value 1 """
    for key, value in dict(segments).items():
        if value == 1:
            del segments[key]

def find_seg_pos(segment, ciphertext):
    """ Finds position of the first letter 
    of the given segment in the text """
    positions = []
    start = ciphertext.find(segment)
    while start >= 0:
        positions.append(start)
        start = ciphertext.find(segment, start + 1)
    return positions

def find_seg_distance(positions):
    """ Find distance between segments at the given positions """
    distances = []
    length = len(positions)
    for i in range(1, length):
        distances.append(positions[i] - positions[0])
    return distances

def find_gcd(num1, num2):
    """ Calcualtes GCD """
    r = num1 % num2
    if r != 0:
        return find_gcd(num2, r)
    else:
        return num2

def format_text(text):
    """ Removes symbols and white spaces from text """
    regex = '[^a-z]'
    return re.compile(regex).sub('', text).lower()

def kasiski(ciphertext, segment_len):
    """ Kasiski key length test """
    # Find all segments of the given length
    segments = find_segments(segment_len, str(ciphertext))
    # Delete segments which are unique
    filter_segments(segments)
    
    result = []
    # Find distances of segments
    [result.append(find_seg_distance(find_seg_pos(key, ciphertext))) for key, value in segments.items()]
    # Flatten list
    result = [val for sublist in result for val in sublist]
    # Find best GCD
    count = Counter(result)
    topCount = count.most_common(6)
    gcd = topCount[0][0]
    for index in range(1, len(topCount)):
        if topCount[index][1] > 1:
            gcd = find_gcd(gcd, topCount[index][0])
    return gcd


###################     Friedman Test    #########################
def index_of_coincidence(ciphertext, alphabet):
    """ Calculates index of coincidence """
    length = len(ciphertext)
    index = 0

    for i in range(len(alphabet)):
        index += (ciphertext.count(alphabet[i]) * (ciphertext.count(alphabet[i]) - 1))

    index = index / (length * (length - 1))

    return index

def friedman(ciphertext, maxKeyLen, alphabet):
    """ Friedman key length test """
    length = len(ciphertext)

    #find index of coincidence
    for m in range(1, maxKeyLen):
        ys = []
        for i in range(m):
            string = ""
            for j in range(0, length, m):
                if not i + j >= length:
                    string += ciphertext[i + j]
            ys.append(string)
        
        index = 0
        for i in ys:
            index += index_of_coincidence(i, alphabet)
        index /= len(ys)
        if index > 0.058 and index < 0.074:
            return m

    return -1

###################     Frequency analysis    #########################

def string_freqs(string):
    """ Calculates frequencies of letters """
    frequencies = [0] * 26
    length = len(string)
    for ch in string:
        frequencies[alphabet.index(ch)] += 1

    for i in range(len(frequencies)):
        frequencies[i] /= (length / 100)
    return frequencies

def caesar_decrypt(shift, text):
    out = ""
    for char in text:
        idx = alphabet.index(char)
        out += alphabet[(idx - shift) % len(alphabet)]
    return out

def get_best_shift(frequencies, statistic_freqs):
    """ Tries to guess letter which the string was shifted 
    based on the typical text frequencies"""
    letter = ''
    score = float('inf')

    for shift in range(1, 27):
        local = 0
        for index in range(0, 26):
            shiftIndex = (index + shift) % 26
            local += abs(frequencies[index] - statistic_freqs[shiftIndex])
        local /= 26
        if local < score:
            score = local
            letter = chr(ord('Z') - shift + 1)
    return letter

def freq_analysis(ciphertext, alphabet, text_frequencies, keylen):
    """ Known key length ciphertext attack """
    length = len(ciphertext)
    ys = []

    for i in range(keylen):
        string = ""
        for j in range(0, length, keylen):
            if not i + j >= length:
                string += ciphertext[i + j]
        ys.append(string)

    key = ''
    frequencies = []
    for subs in ys:
        frequencies.append(string_freqs(subs))

    for frequency in frequencies:
        key += get_best_shift(frequency, text_frequencies)

    return key
        
####################### Cryptanalysis ############################

def vigenere_encrypt(key, text):
    out = ""
    key_int = [alphabet.index(i) for i in key]
    ciphertext_int = [alphabet.index(i) for i in text]
    for i in range(len(text)):
        val = (ciphertext_int[i] + key_int[i % len(key)]) % len(alphabet)
        out += alphabet[val]
    return out

text = """In almost any piece of writing submitted by a non-native speaker of English, three things will
often indicate that the writer is working in a second language: the choice of tense and aspect, the
subject and verb agreements, and the use of articles. While verb problems can largely
be overcome and the mistakes in agreements eliminated by careful proofreading, the problems
with articles frequently remain. Since articles rank among the five most common words in the
English language, errors in this area are highly noticeable to native speakers. Given that 
Australian universities are experiencing an influx of international students who speak
English as a second or even third language, it is imperative for academic advisors who specialise
in TESL to understand the major language difficulties of these students. Since many of our
international students come from Asian countries, this means that their most frequent language
problem is in the area of articles."""

formated_text = format_text(text)
ciphertext = vigenere_encrypt("kryjezabava", formated_text)
max_key_length = 30
segment_length = 4

kasiski_result = kasiski(ciphertext, segment_length)
print("Kasiski key length =", kasiski_result)
print("Friedman key length =", friedman(ciphertext, max_key_length, alphabet))

print(freq_analysis(ciphertext, alphabet, eng_freq, kasiski_result))
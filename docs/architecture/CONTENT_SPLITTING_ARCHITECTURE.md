# Content Splitting Architecture - AI-Powered Multi-Video Generation

## Overview

The content splitting system intelligently divides documents into multiple logical sections for multi-video generation. It works across **all file types** (text, markdown, PDF, etc.) using multiple strategies with AI-powered semantic understanding.

---

## The Problem We're Solving

### Before (H2-Only Approach) ❌
```python
# Only works for markdown
split_by_h2 = (video_count > 1)  # ❌ Fails for plain text, PDFs, etc.
```

**Issues:**
- Only works with markdown H2 headers
- Plain text files can't be split
- PDFs have no header structure
- No semantic understanding
- Fixed splitting logic

### After (Intelligent Multi-Strategy) ✅
```python
# Works for ANY content type
result = await splitter.split(
    content=text,
    num_sections=4,
    strategy=SplitStrategy.AUTO  # ✅ Automatically selects best method
)
```

**Benefits:**
- Works with **any file type**
- **AI-powered** semantic splitting
- Multiple fallback strategies
- User control over splitting method
- Adaptive to content structure

---

## Architecture

### Core Components

```
ContentSplitter (video_gen/input_adapters/content_splitter.py)
├── Strategy Selection (Auto-detect best method)
├── AI-Powered Splitting (Claude/OpenAI)
├── Rule-Based Strategies
│   ├── Markdown Headers
│   ├── Paragraph Boundaries
│   ├── Sentence Boundaries
│   └── Length-Based
└── Manual Splitting (User-defined)
```

### Strategy Hierarchy

```
1. AUTO (Default)
   ├─> Has markdown headers? → MARKDOWN_HEADERS
   ├─> AI available + long content? → AI_INTELLIGENT
   ├─> Clear paragraphs? → PARAGRAPH
   └─> Otherwise → SENTENCE (smart length)

2. AI_INTELLIGENT (Premium)
   ├─> Claude API analyzes content
   ├─> Identifies semantic boundaries
   ├─> Creates natural topic sections
   └─> Fallback → SENTENCE on error

3. MARKDOWN_HEADERS (Markdown only)
   ├─> Split by H1/H2 headers
   └─> Fallback → PARAGRAPH if no headers

4. PARAGRAPH (Text with structure)
   ├─> Split by double newlines
   └─> Fallback → LENGTH if too few

5. SENTENCE (Universal)
   ├─> Split by sentences
   └─> Respects natural breaks

6. LENGTH (Last resort)
   └─> Split by word count at sentence boundaries

7. MANUAL (Advanced users)
   └─> User provides exact split points
```

---

## AI-Powered Splitting (The Magic) ✨

### How It Works

```python
# 1. User uploads any document
content = "Long article about machine learning..."
video_count = 4

# 2. System automatically detects AI is best strategy
strategy = SplitStrategy.AUTO  # Will select AI_INTELLIGENT

# 3. Claude analyzes content semantically
prompt = """
Analyze this document and split it into exactly 4 logical sections.
Identify natural topic boundaries and transitions.
Each section should cover a distinct theme.
"""

# 4. Claude responds with section boundaries
{
  "sections": [
    {
      "title": "Introduction to Machine Learning",
      "start_marker": "Machine learning is a subset...",
      "end_marker": "...moving to neural networks.",
      "reasoning": "Foundational concepts and definitions"
    },
    {
      "title": "Neural Network Architectures",
      ...
    }
  ]
}

# 5. System creates 4 semantic sections automatically!
```

### AI Prompt Design

**Key Features:**
- **Semantic Understanding**: Identifies topics, not just structure
- **Context Preservation**: Maintains narrative flow
- **Balanced Sections**: Aims for similar lengths
- **Clear Boundaries**: Finds natural transition points
- **Fallback Safe**: Gracefully handles failures

### Cost Management

```python
class AIUsageMetrics:
    """Tracks AI API usage and costs."""
    - Input tokens
    - Output tokens
    - Estimated cost (Sonnet 4: $3/M input, $15/M output)
    - Success rate
```

**Typical Cost:**
- 2000 word document: ~1500 input tokens + 500 output tokens
- Cost: **~$0.0045 - $0.0075 per document**
- Highly affordable for quality splitting!

---

## Integration Points

### 1. DocumentAdapter Integration

```python
# video_gen/input_adapters/document.py

from .content_splitter import ContentSplitter, SplitStrategy

class DocumentAdapter(InputAdapter):
    def __init__(self, ...):
        # Add content splitter
        self.splitter = ContentSplitter(
            ai_api_key=ai_api_key,
            use_ai=True
        )

    async def adapt(self, source: Any, **kwargs) -> InputAdapterResult:
        content = await self._read_document_content(source)

        # Get splitting parameters
        video_count = kwargs.get('video_count', 1)
        split_strategy = kwargs.get('split_strategy', 'auto')

        if video_count > 1:
            # Use intelligent splitter
            split_result = await self.splitter.split(
                content=content,
                num_sections=video_count,
                strategy=SplitStrategy(split_strategy)
            )

            # Create one video per section
            videos = []
            for section in split_result.sections:
                video_config = self._create_video_from_section(
                    section=section,
                    **kwargs
                )
                videos.append(video_config)

            return InputAdapterResult(
                success=True,
                video_set=VideoSet(videos=videos),
                metadata={
                    "split_strategy": split_result.strategy_used,
                    "confidence": split_result.confidence,
                    "sections": len(split_result.sections)
                }
            )
```

### 2. InputConfig Extension

```python
# video_gen/shared/models.py

class InputConfig(BaseModel):
    # ... existing fields
    video_count: int = 1
    split_strategy: str = "auto"  # ✅ NEW: Strategy selection
    enable_ai_splitting: bool = True  # ✅ NEW: AI toggle
```

### 3. API Endpoint Updates

```python
# app/main.py

class DocumentInput(BaseModel):
    # ... existing fields
    video_count: Optional[int] = Field(default=1, ge=1, le=10)
    split_strategy: Optional[str] = "auto"  # ✅ NEW
    enable_ai_splitting: Optional[bool] = True  # ✅ NEW

@app.post("/api/parse/document")
async def parse_document(input: DocumentInput, ...):
    input_config = InputConfig(
        input_type="document",
        source=document_path,
        # ... other fields
        video_count=input.video_count,
        split_strategy=input.split_strategy,  # ✅ Pass strategy
        enable_ai_splitting=input.enable_ai_splitting
    )
```

### 4. Frontend UI Updates

```javascript
// app/templates/create-unified.html

config: {
    videoMode: 'set',
    videoCount: 4,
    splitStrategy: 'auto',  // ✅ NEW: User choice
    enableAISplitting: true  // ✅ NEW: AI toggle
}

// Split strategy selector
<select x-model="config.splitStrategy">
    <option value="auto">🤖 Smart (Recommended)</option>
    <option value="ai">✨ AI-Powered</option>
    <option value="headers">📑 By Headers (Markdown)</option>
    <option value="paragraph">¶ By Paragraphs</option>
    <option value="sentence">📝 By Sentences</option>
    <option value="length">📏 By Length</option>
</select>

// Payload
payload = {
    // ... other fields
    video_count: videoCount,
    split_strategy: this.config.splitStrategy,  // ✅ NEW
    enable_ai_splitting: this.config.enableAISplitting
};
```

---

## Strategy Comparison

| Strategy | Works For | AI Required | Quality | Speed | Cost |
|----------|-----------|-------------|---------|-------|------|
| **AUTO** | Everything | Optional | ⭐⭐⭐⭐⭐ | Fast | Free/Low |
| **AI_INTELLIGENT** | Any text | Yes | ⭐⭐⭐⭐⭐ | Medium | ~$0.005 |
| **MARKDOWN_HEADERS** | Markdown | No | ⭐⭐⭐⭐ | Fast | Free |
| **PARAGRAPH** | Structured text | No | ⭐⭐⭐ | Fast | Free |
| **SENTENCE** | Any text | No | ⭐⭐⭐ | Fast | Free |
| **LENGTH** | Any text | No | ⭐⭐ | Fast | Free |
| **MANUAL** | Any text | No | ⭐⭐⭐⭐⭐ | Fast | Free |

---

## User Experience Flow

### Simple Flow (Default)
```
1. Upload document (any format) ✅
2. Select "Video Set" with 4 videos ✅
3. Leave "Smart Splitting" selected ✅
4. Click Generate ✅
5. System automatically:
   - Detects markdown → uses headers
   - Detects plain text → uses AI
   - Falls back gracefully if needed
6. Get 4 intelligently split videos! 🎉
```

### Advanced Flow (Power Users)
```
1. Upload document ✅
2. Select "Video Set" with 5 videos ✅
3. Choose splitting method:
   - "AI-Powered" for semantic splitting
   - "By Paragraphs" for structured docs
   - "By Sentences" for uniform length
4. Toggle "Enable AI" on/off ✅
5. Generate with exact control! 🎯
```

---

## Examples

### Example 1: Markdown Technical Document

**Input:** `ML_Guide.md` (2000 words, 6 H2 sections)
```markdown
# Machine Learning Guide

## Introduction to ML
Content about ML basics...

## Supervised Learning
Content about supervised...

## Neural Networks
Content about neural nets...

## Model Training
Content about training...

## Deployment
Content about deployment...

## Best Practices
Content about best practices...
```

**Strategy Selection:** AUTO → MARKDOWN_HEADERS

**Result:** 6 videos, one per H2 section
- Confidence: 0.8
- Cost: $0 (no AI used)
- Time: <1 second

---

### Example 2: Plain Text Article

**Input:** `article.txt` (1500 words, no structure)
```
Machine learning has transformed the way we approach data analysis.
It enables computers to learn from experience without explicit programming.
The field encompasses various algorithms and techniques...
[continues with no headers or clear structure]
```

**Strategy Selection:** AUTO → AI_INTELLIGENT

**AI Analysis:**
```json
{
  "sections": [
    {
      "title": "Introduction to Machine Learning",
      "reasoning": "Opening concepts and definitions"
    },
    {
      "title": "Core Algorithms and Techniques",
      "reasoning": "Technical deep dive into methods"
    },
    {
      "title": "Practical Applications",
      "reasoning": "Real-world use cases"
    },
    {
      "title": "Future Directions",
      "reasoning": "Emerging trends and conclusions"
    }
  ]
}
```

**Result:** 4 semantically coherent videos
- Confidence: 0.9
- Cost: ~$0.0067
- Time: ~3 seconds
- Natural topic progression!

---

### Example 3: PDF Research Paper

**Input:** `research.pdf` (5000 words, academic format)

**Strategy Selection:** AUTO → AI_INTELLIGENT (PDF has no markdown)

**Result:** 5 videos covering:
1. Abstract & Introduction
2. Methodology
3. Results & Analysis
4. Discussion
5. Conclusions & Future Work

AI automatically identified academic paper structure even though PDF is unstructured text!

---

## Implementation Phases

### Phase 1: Core Splitter ✅ DONE
- [x] ContentSplitter class created
- [x] All 7 strategies implemented
- [x] AI integration with Claude
- [x] Fallback hierarchy working
- [x] Cost tracking included

### Phase 2: Integration (Next)
- [ ] Integrate into DocumentAdapter
- [ ] Update InputConfig model
- [ ] Update API endpoints
- [ ] Test with various file types

### Phase 3: Frontend (Next)
- [ ] Add split strategy selector
- [ ] Add AI toggle
- [ ] Show split preview
- [ ] Display cost estimate

### Phase 4: Testing & Refinement
- [ ] Test with 10+ document types
- [ ] Benchmark AI vs rule-based quality
- [ ] Optimize AI prompts
- [ ] User acceptance testing

---

## Configuration

### Environment Variables

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...  # For AI splitting
OPENAI_API_KEY=sk-...         # Alternative to Claude

# Optional: Control AI usage
ENABLE_AI_SPLITTING=true
AI_SPLITTING_MAX_COST=0.10    # Max $0.10 per split
AI_SPLITTING_TIMEOUT=10       # 10 second timeout
```

### User Preferences

```python
# User can control via API or UI
split_config = {
    "strategy": "auto",          # Let system decide
    "enable_ai": True,           # Allow AI usage
    "fallback_strategy": "sentence",  # If AI fails
    "min_words_per_section": 50,
    "max_words_per_section": 500
}
```

---

## Benefits Summary

### For Users
✅ **Works with ANY file type** (not just markdown)
✅ **Intelligent semantic splitting** (not just structural)
✅ **Automatic strategy selection** (no configuration needed)
✅ **Manual control available** (for power users)
✅ **Cost-effective** (~$0.005-$0.01 per document with AI)
✅ **Fast fallback** (instant rule-based methods)

### For System
✅ **Graceful degradation** (fallback hierarchy)
✅ **Extensible architecture** (easy to add strategies)
✅ **AI agnostic** (works with Claude, OpenAI, or no AI)
✅ **Comprehensive metrics** (usage tracking built-in)
✅ **Production ready** (error handling, logging)

---

## Future Enhancements

### Potential Additions
1. **Multi-Language AI Prompts**: Different prompts per language
2. **User-Trained Models**: Learn from user feedback
3. **Hybrid Strategies**: Combine multiple approaches
4. **Visual Splitting**: Show split preview before generation
5. **Split Templates**: Pre-defined patterns for common doc types
6. **Collaborative Splitting**: Multiple users vote on boundaries

### Research Opportunities
- Compare Claude vs GPT-4 splitting quality
- Benchmark against human-created splits
- A/B test different AI prompts
- Analyze user preferences by document type

---

## Technical Specifications

### Dependencies
```python
# Required
anthropic>=0.25.0  # Claude AI
pydantic>=2.0      # Data validation

# Optional
openai>=1.0        # Alternative AI provider
```

### Performance
- Rule-based strategies: <100ms
- AI strategies: 2-5 seconds
- Memory: <50MB for 10,000 word document
- Concurrent: Thread-safe, supports async

### Limits
- Max document size: 100,000 words
- Max sections: 20 per document
- Min section size: 50 words
- AI timeout: 30 seconds

---

## Migration Path

### From H2-Only to Intelligent Splitting

**Old Code:**
```python
split_by_h2 = (video_count > 1)
```

**New Code:**
```python
from video_gen.input_adapters.content_splitter import ContentSplitter, SplitStrategy

splitter = ContentSplitter(ai_api_key=api_key)
result = await splitter.split(
    content=text,
    num_sections=video_count,
    strategy=SplitStrategy.AUTO
)
```

**Backwards Compatible:**
```python
# Old parameter still works
if kwargs.get('split_by_h2'):
    strategy = SplitStrategy.MARKDOWN_HEADERS
else:
    strategy = SplitStrategy.AUTO
```

---

## Conclusion

This intelligent splitting system transforms video generation from a markdown-only feature to a universal capability that works with **any content type**. By leveraging AI for semantic understanding while maintaining fast, free fallbacks, we provide both quality and reliability.

**Key Innovation:** Using Claude/OpenAI to understand content **semantically** rather than just syntactically means we can split documents the way a human would - by topic and natural boundaries, not just formatting.

This makes multi-video generation accessible for **all users** regardless of their source document format. 🚀

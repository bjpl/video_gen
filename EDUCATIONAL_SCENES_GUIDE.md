# Educational Scene Types - Complete Guide

**Transform your video system into a complete educational platform**

**New:** 6 educational scene types for lessons, courses, quizzes, and more!

---

## 🎓 Overview

Your video generation system now includes **6 specialized educational scene types**:

1. **`learning_objectives`** - Lesson goals and expectations
2. **`problem`** - Coding challenge presentation
3. **`solution`** - Problem solution with explanation
4. **`checkpoint`** - Learning progress review
5. **`quiz`** - Multiple choice questions with answers
6. **`exercise`** - Practice instructions

**Plus the existing 6 general scene types** = **12 total scene types!**

---

## 🚀 Quick Start

### **Simple Educational Lesson:**

```python
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("lesson", "Python Lesson")

builder.add_video(
    video_id="functions",
    title="Functions",
    scenes=[
        # Learning objectives
        builder.create_learning_objectives_scene(
            "Lesson 1: Functions",
            ["Define functions", "Use parameters", "Return values"],
            {'duration': 15, 'difficulty': 'beginner'}
        ),

        # Explanation
        builder.create_command_scene(
            "Function Basics",
            "How to Define",
            ["def greet(name):", "    return f'Hello, {name}!'"]
        ),

        # Problem
        builder.create_problem_scene(
            1,
            "Create Add Function",
            "Write a function that adds two numbers",
            difficulty="easy"
        ),

        # Solution
        builder.create_solution_scene(
            "Solution",
            ["def add(a, b):", "    return a + b"],
            "Add two parameters and return the sum"
        ),

        # Quiz
        builder.create_quiz_scene(
            "What keyword defines a function?",
            ["A: function", "B: def", "C: func", "D: define"],
            "B: def",
            show_answer=True
        ),

        # Checkpoint
        builder.create_checkpoint_scene(
            1,
            ["Functions", "Parameters"],
            ["Can you write functions?"],
            ["Loops", "Conditionals"]
        )
    ]
)

builder.export_to_yaml('sets/lesson')
```

---

## 📚 Scene Type Reference

### **1. Learning Objectives Scene**

**Purpose:** Present lesson goals, duration, difficulty, prerequisites

```python
builder.create_learning_objectives_scene(
    lesson_title="Lesson 1: Variables",
    objectives=[
        "Declare variables with proper syntax",
        "Assign values of different types",
        "Use variables in expressions",
        "Understand variable scope"
    ],
    lesson_info={
        'duration': 15,              # Minutes
        'difficulty': 'beginner',    # easy/beginner/intermediate/advanced
        'prerequisites': ['Python installation', 'Basic syntax']
    },
    narration="Lesson one: Variables. By the end you will declare variables, assign values, use them in expressions, and understand scope. Duration: fifteen minutes. Difficulty: beginner."
)
```

**Visual:**
```
┌─────────────────────────────────────┐
│     Learning Objectives             │
│     Lesson 1: Variables             │
│                                     │
│  ⏱ 15 min • 📊 Beginner • 📚 2 prereq│
│                                     │
│  ① Declare variables properly       │
│  ② Assign different value types     │
│  ③ Use variables in expressions     │
│  ④ Understand variable scope        │
└─────────────────────────────────────┘
```

---

### **2. Problem Scene**

**Purpose:** Present coding challenges/exercises

```python
builder.create_problem_scene(
    problem_number=1,
    title="Calculate Circle Area",
    problem_text="Write a function called circle_area that takes radius as a parameter and returns the area. Use the formula: area = π × r². Test with radius = 5.",
    difficulty="medium",  # easy, medium, hard
    narration="Problem one. Calculate circle area. Write a function called circle underscore area that takes radius as a parameter. Use the formula: area equals pi times r squared. Test with radius equals five. Difficulty: medium."
)
```

**Visual:**
```
┌─────────────────────────────────────┐
│          [MEDIUM]                   │
│        Problem #1                   │
│   Calculate Circle Area             │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ Write a function called     │   │
│  │ circle_area that takes      │   │
│  │ radius as a parameter...    │   │
│  │                            ?│   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

**Difficulty colors:**
- Easy: Green
- Medium: Orange
- Hard: Pink

---

### **3. Solution Scene**

**Purpose:** Show problem solutions with explanations

```python
builder.create_solution_scene(
    title="Solution: Circle Area",
    solution_code=[
        "import math",
        "",
        "def circle_area(radius):",
        "    area = math.pi * radius ** 2",
        "    return area",
        "",
        "# Test",
        "result = circle_area(5)",
        "print(f'Area: {result:.2f}')",
        "→ Area: 78.54"
    ],
    explanation="Import math for pi constant. Multiply pi by radius squared. Return the calculated area.",
    narration="Solution. Import math for the pi constant. Define circle underscore area with radius parameter. Calculate area as pi times radius squared. Return the area. Test with radius five gives seventy eight point five four."
)
```

**Visual:**
```
┌─────────────────────────────────────┐
│        [SOLUTION]                   │
│   Solution: Circle Area             │
│                                     │
│  ┌─────────────────────────────┐   │
│  │ import math                 │   │
│  │                             │   │
│  │ def circle_area(radius):    │   │
│  │     area = math.pi * r**2   │   │
│  │     return area             │   │
│  └─────────────────────────────┘   │
│                                     │
│  Multiply pi by radius squared...   │
└─────────────────────────────────────┘
```

---

### **4. Checkpoint Scene**

**Purpose:** Review progress, show what's completed, what's next

```python
builder.create_checkpoint_scene(
    checkpoint_number=1,
    completed_topics=[
        "Variable declaration",
        "Function definition",
        "Return values",
        "Function calls"
    ],
    review_questions=[
        "Can you declare variables?",
        "Can you write functions?",
        "Can you use return?"
    ],
    next_topics=[
        "Default parameters",
        "Keyword arguments",
        "Lambda functions"
    ],
    narration="Checkpoint one. You have completed variable declaration, function definition, return values, and function calls. Review: can you declare variables? Can you write functions? Can you use return? Next: default parameters, keyword arguments, and lambda functions."
)
```

**Visual (3 columns):**
```
┌──────────┬──────────┬──────────┐
│Completed │  Review  │   Next   │
├──────────┼──────────┼──────────┤
│✓ Vars    │• Quiz 1  │• Defaults│
│✓ Funcs   │• Quiz 2  │• Kwargs  │
│✓ Return  │• Quiz 3  │• Lambda  │
└──────────┴──────────┴──────────┘
```

---

### **5. Quiz Scene**

**Purpose:** Knowledge check with multiple choice

```python
builder.create_quiz_scene(
    question="What does the 'return' keyword do in a function?",
    options=[
        "A: Prints the value to console",
        "B: Sends a value back to caller",
        "C: Ends the entire program",
        "D: Deletes the function"
    ],
    correct_answer="B: Sends a value back to caller",
    show_answer=True,  # Show correct answer visually
    narration="Quiz question. What does the return keyword do in a function? Option A: prints the value. Option B: sends a value back to caller. Option C: ends the program. Option D: deletes the function. The correct answer is B: sends a value back to caller."
)
```

**Visual (2x2 grid):**
```
┌─────────────────────────────────────┐
│           QUIZ                      │
│  What does 'return' do?             │
│                                     │
│  ┌──────────┐  ┌──────────┐        │
│  │ A: Print │  │ B: Send  │ ✓      │
│  └──────────┘  └──────────┘        │
│  ┌──────────┐  ┌──────────┐        │
│  │ C: End   │  │ D: Delete│        │
│  └──────────┘  └──────────┘        │
└─────────────────────────────────────┘
```

**Answer highlighted in green with checkmark**

---

### **6. Exercise Scene**

**Purpose:** Present practice instructions

```python
builder.create_exercise_scene(
    title="Practice: List Operations",
    instructions=[
        "Create a list with 5 numbers",
        "Use a for loop to print each number",
        "Calculate and print the sum",
        "Find and print the maximum value"
    ],
    difficulty="medium",
    estimated_time="15 minutes",
    narration="Practice exercise. List operations. Create a list with five numbers. Use a for loop to print each number. Calculate and print the sum. Find and print the maximum value. Estimated time: fifteen minutes. Difficulty: medium."
)
```

**Visual:**
```
┌─────────────────────────────────────┐
│     Practice Exercise               │
│  Practice: List Operations          │
│                                     │
│  [MEDIUM] [⏱ 15 minutes]            │
│                                     │
│  Instructions:                      │
│   1. Create a list with 5 numbers   │
│   2. Use for loop to print each     │
│   3. Calculate and print sum        │
│   4. Find and print maximum         │
└─────────────────────────────────────┘
```

---

## 💡 Complete Lesson Example

### **Full Lesson Structure:**

```python
from scripts.python_set_builder import VideoSetBuilder

builder = VideoSetBuilder("complete_lesson", "Complete Lesson")

builder.add_video(
    video_id="lesson_variables",
    title="Lesson: Variables",
    scenes=[
        # 1. Set expectations
        builder.create_learning_objectives_scene(
            "Variables in Python",
            [
                "Declare variables correctly",
                "Use different data types",
                "Understand variable naming rules"
            ],
            {'duration': 10, 'difficulty': 'beginner'}
        ),

        # 2. Introduce topic
        builder.create_title_scene(
            "Variables",
            "Storing Data",
            narration="Variables store data values in your programs."
        ),

        # 3. Explain with examples
        builder.create_command_scene(
            "Creating Variables",
            "Basic Syntax",
            [
                "x = 10",
                "name = 'Alice'",
                "is_active = True"
            ],
            narration="Create variables with assignment. Number, string, and boolean examples."
        ),

        # 4. Present challenge
        builder.create_problem_scene(
            1,
            "Variable Practice",
            "Create variables for your name, age, and city. Print all three.",
            "easy"
        ),

        # 5. Show solution
        builder.create_solution_scene(
            "Solution",
            [
                "name = 'Alice'",
                "age = 25",
                "city = 'New York'",
                "print(name, age, city)"
            ],
            "Create three variables and print them together."
        ),

        # 6. Check knowledge
        builder.create_quiz_scene(
            "Which is a valid variable name?",
            [
                "A: 123abc",
                "B: my-variable",
                "C: my_variable",
                "D: my variable"
            ],
            "C: my_variable",
            show_answer=True
        ),

        # 7. Practice time
        builder.create_exercise_scene(
            "Variable Practice",
            [
                "Create 5 variables of different types",
                "Print each variable with its type",
                "Try changing variable values",
                "Experiment with type conversion"
            ],
            difficulty="easy",
            estimated_time="10 minutes"
        ),

        # 8. Review progress
        builder.create_checkpoint_scene(
            1,
            ["Variable declaration", "Data types", "Naming rules"],
            ["Can you create variables?", "Do you understand types?"],
            ["Functions", "Conditionals"]
        ),

        # 9. Wrap up
        builder.create_outro_scene(
            "Variables Mastered!",
            "Next: Functions",
            narration="You have mastered variables! Next lesson covers functions."
        )
    ]
)

builder.export_to_yaml('sets/complete_lesson')
```

**Result:** Complete educational lesson with all pedagogical elements!

---

## 📋 API Reference

### **learning_objectives Scene**

```python
create_learning_objectives_scene(
    lesson_title: str,           # "Lesson 1: Variables"
    objectives: List[str],       # List of learning objectives
    lesson_info: Dict = None,    # Optional: {duration, difficulty, prerequisites}
    narration: str = None        # Optional custom narration
)
```

### **problem Scene**

```python
create_problem_scene(
    problem_number: int,         # Problem number (1, 2, 3...)
    title: str,                  # Problem title
    problem_text: str,           # Problem description
    difficulty: str = 'medium',  # 'easy', 'medium', 'hard'
    narration: str = None
)
```

### **solution Scene**

```python
create_solution_scene(
    title: str,                  # Solution title
    solution_code: List[str],    # Lines of solution code
    explanation: str = "",       # Explanation text
    narration: str = None
)
```

### **checkpoint Scene**

```python
create_checkpoint_scene(
    checkpoint_number: int,      # Checkpoint number
    completed_topics: List[str], # What was completed
    review_questions: List[str], # Self-check questions
    next_topics: List[str],      # What's coming next
    narration: str = None
)
```

### **quiz Scene**

```python
create_quiz_scene(
    question: str,               # Quiz question
    options: List[str],          # Answer options (A, B, C, D)
    correct_answer: str,         # Correct option
    show_answer: bool = True,    # Highlight correct answer
    narration: str = None
)
```

### **exercise Scene**

```python
create_exercise_scene(
    title: str,                  # Exercise title
    instructions: List[str],     # Step-by-step instructions
    difficulty: str = 'medium',  # Difficulty level
    estimated_time: str = None,  # "10 minutes"
    narration: str = None
)
```

---

## 🎯 Educational Workflows

### **Workflow 1: Programming Tutorial**

**Structure:**
1. Learning objectives
2. Concept explanation (title)
3. Code examples (command)
4. Problem
5. Solution
6. Quiz
7. Exercise
8. Checkpoint

**Example:**

```python
# Complete programming lesson
scenes = [
    builder.create_learning_objectives_scene(...),
    builder.create_title_scene("Lists", "Data Collections"),
    builder.create_command_scene("List Basics", "Create and Use", [...]),
    builder.create_problem_scene(1, "List Sum", "Calculate sum of list", "easy"),
    builder.create_solution_scene("Solution", [...], "Loop and add"),
    builder.create_quiz_scene("How to access first element?", [...], "A: list[0]"),
    builder.create_exercise_scene("Practice", [...], "medium", "15 min"),
    builder.create_checkpoint_scene(1, [...], [...], [...])
]
```

---

### **Workflow 2: Concept-Based Lesson**

**Structure:**
1. Learning objectives
2. Introduction
3. Key concepts (list)
4. Examples (command)
5. Quiz
6. Checkpoint

```python
# Theoretical concept lesson
scenes = [
    builder.create_learning_objectives_scene(
        "OOP Principles",
        ["Understand encapsulation", "Understand inheritance"],
        {'duration': 12, 'difficulty': 'intermediate'}
    ),
    builder.create_title_scene("OOP", "Object-Oriented Programming"),
    builder.create_list_scene(
        "Four Pillars",
        "Core Principles",
        [("Encapsulation", "Bundle data"), ("Inheritance", "Reuse code")]
    ),
    builder.create_code_comparison_scene(
        "Procedural vs OOP",
        before_code=["def process():..."],
        after_code=["class Processor:", "    def process():..."]
    ),
    builder.create_quiz_scene(
        "What is encapsulation?",
        ["A: Bundling data and methods", "B: ..."],
        "A: Bundling data and methods"
    ),
    builder.create_checkpoint_scene(1, ["OOP basics"], ["Understand pillars?"], ["Classes"])
]
```

---

### **Workflow 3: Problem-Solution Series**

**Structure:**
Multiple problem-solution pairs

```python
# Series of coding challenges
for i, (problem_desc, solution_code, explanation) in enumerate(challenges, 1):
    builder.add_video(
        video_id=f"challenge_{i:02d}",
        title=f"Challenge {i}",
        scenes=[
            builder.create_problem_scene(i, f"Challenge {i}", problem_desc, "medium"),
            builder.create_solution_scene(f"Solution {i}", solution_code, explanation)
        ]
    )
```

---

## 🎨 Scene Combinations

### **Standard Lesson Pattern:**

```
1. Learning Objectives    [What you'll learn]
2. Title                  [Topic introduction]
3. Command                [Examples]
4. List                   [Key points]
5. Problem                [Challenge]
6. Solution               [Answer]
7. Quiz                   [Knowledge check]
8. Checkpoint             [Progress review]
9. Outro                  [Next steps]
```

### **Quick Concept Pattern:**

```
1. Title                  [Topic]
2. List                   [Key points]
3. Command                [Example]
4. Quiz                   [Quick check]
5. Outro                  [Summary]
```

### **Practice-Heavy Pattern:**

```
1. Title                  [Topic]
2. Command                [Example]
3. Problem #1             [Easy]
4. Solution #1
5. Problem #2             [Medium]
6. Solution #2
7. Exercise               [Practice]
8. Checkpoint
```

---

## 🌍 Multilingual Educational Content

**Educational scenes work with multilingual system!**

```python
from scripts.multilingual_builder import MultilingualVideoSet

# Create course in 5 languages
ml = MultilingualVideoSet(
    "programming_course",
    "Programming Course",
    languages=['en', 'es', 'fr', 'de', 'pt']
)

# Add lesson in English
ml.add_video_source(
    video_id='lesson_01',
    title='Functions',
    scenes=[
        {
            'scene_type': 'learning_objectives',
            'visual_content': {
                'lesson_title': 'Functions',
                'objectives': ['Define functions', 'Use parameters'],
                'lesson_info': {'duration': 15, 'difficulty': 'beginner'}
            },
            'narration': '...'
        },
        {
            'scene_type': 'problem',
            'visual_content': {
                'problem_number': 1,
                'title': 'Create Function',
                'problem_text': 'Write a function that adds two numbers',
                'difficulty': 'easy'
            },
            'narration': '...'
        },
        # ... more scenes
    ]
)

# Auto-translate to 4 other languages
await ml.auto_translate_and_export()

# Result: Complete lesson in 5 languages!
```

---

## 📊 Complete Course Example

```python
from scripts.python_set_builder import VideoSetBuilder

# Python programming course
builder = VideoSetBuilder(
    "python_101",
    "Python 101 - Complete Course",
    naming={'prefix': 'lesson', 'use_numbers': True}
)

# Define 10 lessons
lessons = [
    ("Variables", "beginner"),
    ("Functions", "beginner"),
    ("Loops", "beginner"),
    ("Conditionals", "beginner"),
    ("Lists", "intermediate"),
    ("Dictionaries", "intermediate"),
    ("Classes", "intermediate"),
    ("File I/O", "intermediate"),
    ("Exceptions", "advanced"),
    ("Decorators", "advanced")
]

for i, (topic, difficulty) in enumerate(lessons, 1):
    builder.add_video(
        video_id=f"{i:02d}_{topic.lower()}",
        title=f"Lesson {i}: {topic}",
        scenes=[
            builder.create_learning_objectives_scene(
                f"Lesson {i}: {topic}",
                [f"Understand {topic}", f"Use {topic} effectively"],
                {'duration': 15, 'difficulty': difficulty}
            ),
            builder.create_title_scene(topic, f"Master {topic}"),
            builder.create_command_scene(f"{topic} Examples", "How To Use", ["# ..."]),
            builder.create_problem_scene(i, f"{topic} Challenge", f"Practice {topic}", difficulty),
            builder.create_solution_scene(f"Solution", ["# ..."], f"How to solve {topic} problems"),
            builder.create_quiz_scene(f"Quiz: {topic}", ["A", "B", "C"], "A"),
            builder.create_checkpoint_scene(i, [topic], [f"Understand {topic}?"], [lessons[i][0] if i < len(lessons) else "Complete"]),
            builder.create_outro_scene("Great!", f"Next: {lessons[i][0] if i < len(lessons) else 'Course Complete'}")
        ]
    )

builder.export_to_yaml('sets/python_101')

# Result: 10-lesson course with full pedagogical structure!
```

---

## 🎯 Best Practices

### **✅ DO:**

```python
# Good: Clear learning objectives
builder.create_learning_objectives_scene(
    "Functions",
    [
        "Define functions with def keyword",
        "Add parameters for inputs",
        "Use return for outputs"
    ]
)

# Good: Progressive difficulty
Problem 1: difficulty='easy'
Problem 2: difficulty='medium'
Problem 3: difficulty='hard'

# Good: Clear checkpoints every 3-4 topics
After Variables, Functions, Loops → Checkpoint

# Good: Quiz after each major concept
After explaining concept → Quiz to reinforce
```

### **❌ DON'T:**

```python
# Avoid: Too many objectives (max 8)
objectives = [...]  # 15 objectives - too many!

# Avoid: Problems without solutions
builder.create_problem_scene(...)  # No solution scene after!

# Avoid: Quiz without answer shown
show_answer=False  # Students can't check understanding

# Avoid: Checkpoints too frequently
# Every single scene → Checkpoint (overkill!)
```

---

## 📚 Educational Video Types

### **Type 1: Complete Lesson**

```python
# 8-10 scenes per lesson
- Learning objectives
- Introduction
- Explanation + examples
- Problem + solution
- Quiz
- Exercise
- Checkpoint
- Outro
```

**Duration:** 10-15 minutes
**Best for:** Formal courses

---

### **Type 2: Quick Concept**

```python
# 4-5 scenes
- Title
- Explanation
- Example
- Quiz
- Outro
```

**Duration:** 3-5 minutes
**Best for:** Quick tips, concept reviews

---

### **Type 3: Challenge Series**

```python
# Multiple problem-solution pairs
- Problem 1
- Solution 1
- Problem 2
- Solution 2
- Problem 3
- Solution 3
- Summary
```

**Duration:** 5-10 minutes
**Best for:** Practice problems, coding challenges

---

## ✅ Summary

**You now have 12 scene types total:**

**General (6):**
1. title
2. command
3. list
4. outro
5. code_comparison
6. quote

**Educational (6 NEW!):**
7. learning_objectives
8. problem
9. solution
10. checkpoint
11. quiz
12. exercise

**Perfect for:**
- Complete courses
- Programming tutorials
- Concept lessons
- Practice problems
- Knowledge checks
- Progress tracking

**Generate professional educational content at scale!** 🎓

---

**See:** `scripts/examples/educational_course_example.py` for complete working examples!

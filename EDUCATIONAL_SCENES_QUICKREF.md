# Educational Scenes - Quick Reference

**Fast lookup for all 6 educational scene types**

---

## 🎓 Six Educational Scene Types

| Scene Type | Purpose | Icon |
|------------|---------|------|
| `learning_objectives` | Lesson goals | 🎯 |
| `problem` | Coding challenges | ❓ |
| `solution` | Problem answers | ✓ |
| `checkpoint` | Progress review | ✓ |
| `quiz` | Knowledge check | 📝 |
| `exercise` | Practice instructions | 💪 |

---

## ⚡ Quick Examples

### **Learning Objectives**
```python
builder.create_learning_objectives_scene(
    "Lesson 1: Variables",
    ["Declare variables", "Assign values", "Use types"],
    {'duration': 15, 'difficulty': 'beginner'}
)
```

### **Problem**
```python
builder.create_problem_scene(
    1, "Add Function", "Write function that adds two numbers", "easy"
)
```

### **Solution**
```python
builder.create_solution_scene(
    "Solution", ["def add(a, b):", "    return a + b"], "Add and return"
)
```

### **Checkpoint**
```python
builder.create_checkpoint_scene(
    1, ["Variables", "Functions"], ["Can you code?"], ["Loops"]
)
```

### **Quiz**
```python
builder.create_quiz_scene(
    "What is a function?",
    ["A: Variable", "B: Reusable code", "C: Loop", "D: Condition"],
    "B: Reusable code",
    show_answer=True
)
```

### **Exercise**
```python
builder.create_exercise_scene(
    "Practice: Lists",
    ["Create list", "Add items", "Print all"],
    difficulty="easy",
    estimated_time="10 min"
)
```

---

## 📋 Complete Lesson Template

```python
scenes = [
    builder.create_learning_objectives_scene(...),  # Goals
    builder.create_title_scene(...),                # Intro
    builder.create_command_scene(...),              # Examples
    builder.create_problem_scene(...),              # Challenge
    builder.create_solution_scene(...),             # Answer
    builder.create_quiz_scene(...),                 # Check
    builder.create_exercise_scene(...),             # Practice
    builder.create_checkpoint_scene(...),           # Review
    builder.create_outro_scene(...)                 # Next
]
```

---

## 🎨 Difficulty Levels

**For problem/exercise scenes:**
- `'easy'` - Green badge
- `'medium'` - Orange badge
- `'hard'` - Pink badge

```python
builder.create_problem_scene(1, "Easy", "...", difficulty="easy")
builder.create_problem_scene(2, "Medium", "...", difficulty="medium")
builder.create_problem_scene(3, "Hard", "...", difficulty="hard")
```

---

## 📊 Lesson Info

**For learning_objectives scene:**

```python
lesson_info={
    'duration': 15,              # Minutes
    'difficulty': 'beginner',    # Text label
    'prerequisites': ['Topic A', 'Topic B']  # List
}
```

---

## ✅ Checklist

**Complete educational lesson:**
- [ ] Learning objectives (what they'll learn)
- [ ] Introduction (title scene)
- [ ] Explanation (command/list scenes)
- [ ] Problem (coding challenge)
- [ ] Solution (with explanation)
- [ ] Quiz (knowledge check)
- [ ] Exercise (practice)
- [ ] Checkpoint (progress review)
- [ ] Outro (next steps)

---

## 🚀 Quick Commands

```bash
# Create example
python examples/educational_course_example.py --example lesson

# Generate
python generate_video_set.py ../sets/python_lesson_complete
python generate_videos_from_set.py ../output/python_lesson_complete
```

---

**See:** `EDUCATIONAL_SCENES_GUIDE.md` for complete documentation!

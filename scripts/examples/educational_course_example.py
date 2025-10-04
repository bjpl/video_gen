"""
Educational Course Example - All Educational Scene Types
=========================================================
Demonstrates all educational scene types in a complete lesson.

Scene types demonstrated:
1. learning_objectives - What students will learn
2. problem - Coding challenge presentation
3. solution - Problem solution with explanation
4. checkpoint - Learning progress review
5. quiz - Knowledge check with multiple choice
6. exercise - Practice instructions

Plus standard scenes:
- title, command, list, outro
"""

import sys
import asyncio
sys.path.append('..')

from python_set_builder import VideoSetBuilder


async def create_complete_educational_lesson():
    """
    Create a complete lesson with all educational scene types
    """

    print("\n" + "="*80)
    print("CREATING COMPLETE EDUCATIONAL LESSON")
    print("="*80 + "\n")

    builder = VideoSetBuilder(
        "python_lesson_complete",
        "Python Lesson - Complete Educational Example",
        defaults={
            'accent_color': 'blue',
            'voice': 'male',
            'target_duration': 180  # 3-minute lesson
        }
    )

    builder.add_video(
        video_id="lesson_01_functions",
        title="Lesson 1: Functions in Python",
        description="Complete lesson with all educational features",
        scenes=[
            # 1. LEARNING OBJECTIVES
            builder.create_learning_objectives_scene(
                lesson_title="Lesson 1: Functions in Python",
                objectives=[
                    "Define functions with parameters",
                    "Use return values effectively",
                    "Understand function scope",
                    "Call functions in your code"
                ],
                lesson_info={
                    'duration': 15,
                    'difficulty': 'beginner',
                    'prerequisites': ['Variables', 'Basic syntax']
                },
                narration="Lesson one: Functions in Python. By the end of this lesson, you will define functions with parameters, use return values effectively, understand function scope, and call functions in your code. Duration: fifteen minutes. Difficulty: beginner. Prerequisites: variables and basic syntax."
            ),

            # 2. TITLE/INTRO
            builder.create_title_scene(
                "Functions",
                "Reusable Code Blocks",
                narration="Functions. Reusable code blocks. Functions let you write code once and use it many times."
            ),

            # 3. EXPLANATION (using command scene)
            builder.create_command_scene(
                "Function Basics",
                "Defining Your First Function",
                [
                    "# Define a function",
                    "def greet(name):",
                    "    return f'Hello, {name}!'",
                    "",
                    "# Call the function",
                    "message = greet('Alice')",
                    "print(message)",
                    "→ Hello, Alice!"
                ],
                narration="Function basics. Define a function with def, add parameters in parentheses, and use return to send back a value. Call the function by name with arguments. The return value can be stored in a variable."
            ),

            # 4. KEY CONCEPTS (using list scene)
            builder.create_list_scene(
                "Key Concepts",
                "Understanding Functions",
                [
                    ("Definition", "Use def keyword"),
                    ("Parameters", "Input values in parentheses"),
                    ("Return", "Send back result with return"),
                    ("Calling", "Use function name with arguments")
                ],
                narration="Key concepts. First, definition uses the def keyword. Second, parameters are input values in parentheses. Third, return sends back a result. Fourth, calling uses the function name with arguments."
            ),

            # 5. PROBLEM
            builder.create_problem_scene(
                problem_number=1,
                title="Calculate Area",
                problem_text="Write a function called calculate_area that takes width and height as parameters and returns the area of a rectangle. Test it with width equals five and height equals three.",
                difficulty="easy",
                narration="Problem one. Calculate area. Write a function called calculate underscore area that takes width and height as parameters and returns the area of a rectangle. Test it with width equals five and height equals three. This is an easy problem."
            ),

            # 6. SOLUTION
            builder.create_solution_scene(
                title="Solution: Calculate Area",
                solution_code=[
                    "def calculate_area(width, height):",
                    "    area = width * height",
                    "    return area",
                    "",
                    "# Test the function",
                    "result = calculate_area(5, 3)",
                    "print(f'Area: {result}')",
                    "→ Area: 15"
                ],
                explanation="Multiply width times height to get area. Return the result. Test with five and three gives fifteen.",
                narration="Solution. Define calculate underscore area with width and height parameters. Multiply width times height to get area. Return the result. Test with five and three. The output is fifteen. This demonstrates how to create a simple calculation function."
            ),

            # 7. QUIZ
            builder.create_quiz_scene(
                question="What keyword do you use to send a value back from a function?",
                options=[
                    "A: send",
                    "B: return",
                    "C: output",
                    "D: result"
                ],
                correct_answer="B: return",
                show_answer=True,
                narration="Quiz time. What keyword do you use to send a value back from a function? Option A: send. Option B: return. Option C: output. Option D: result. The correct answer is B: return. Functions use the return keyword to send values back to the caller."
            ),

            # 8. EXERCISE
            builder.create_exercise_scene(
                title="Practice: Temperature Converter",
                instructions=[
                    "Create a function named celsius_to_fahrenheit",
                    "It should take one parameter: celsius",
                    "Formula: F = C × 9/5 + 32",
                    "Return the Fahrenheit value",
                    "Test with 0, 100, and -40 degrees"
                ],
                difficulty="medium",
                estimated_time="10 minutes",
                narration="Practice exercise. Temperature converter. Create a function named celsius underscore to underscore fahrenheit. It should take one parameter: celsius. Use the formula: F equals C times nine fifths plus thirty two. Return the Fahrenheit value. Test with zero, one hundred, and negative forty degrees. Estimated time: ten minutes. Difficulty: medium."
            ),

            # 9. CHECKPOINT
            builder.create_checkpoint_scene(
                checkpoint_number=1,
                completed_topics=[
                    "Function definition",
                    "Parameters",
                    "Return values",
                    "Function calls"
                ],
                review_questions=[
                    "Can you define a function?",
                    "Can you use parameters?",
                    "Can you return values?"
                ],
                next_topics=[
                    "Default parameters",
                    "Keyword arguments",
                    "Lambda functions"
                ],
                narration="Checkpoint one. You have completed function definition, parameters, return values, and function calls. Review: can you define a function? Can you use parameters? Can you return values? Next, you will learn default parameters, keyword arguments, and lambda functions."
            ),

            # 10. OUTRO
            builder.create_outro_scene(
                "Great Job!",
                "Next: Default Parameters",
                narration="Great job! You have completed lesson one on functions. Next lesson covers default parameters, keyword arguments, and advanced function features."
            )
        ]
    )

    # Export
    builder.export_to_yaml('../sets/python_lesson_complete')

    print("\n✓ Complete educational lesson created!")
    print("  Scenes: 10 (includes all 6 educational scene types)")
    print("  Location: sets/python_lesson_complete/")
    print("\nGenerate with:")
    print("  cd scripts")
    print("  python generate_video_set.py ../sets/python_lesson_complete")
    print("  python generate_videos_from_set.py ../output/python_lesson_complete")


async def create_educational_course_series():
    """
    Create a complete course with multiple lessons
    """

    print("\n" + "="*80)
    print("CREATING EDUCATIONAL COURSE SERIES")
    print("="*80 + "\n")

    builder = VideoSetBuilder(
        "python_course_educational",
        "Python Programming Course",
        defaults={'accent_color': 'blue', 'voice': 'male'},
        naming={'prefix': 'lesson', 'use_numbers': True, 'separator': '-'}
    )

    # Lesson 1: Variables
    builder.add_video(
        video_id="01_variables",
        title="Variables",
        description="Learn about variables",
        scenes=[
            builder.create_learning_objectives_scene(
                "Lesson 1: Variables",
                ["Declare variables", "Assign values", "Use different types"],
                {'duration': 10, 'difficulty': 'beginner'}
            ),
            builder.create_title_scene("Variables", "Storing Data"),
            builder.create_command_scene(
                "Creating Variables",
                "Basic Syntax",
                ["x = 10", "name = 'Alice'", "print(x, name)"]
            ),
            builder.create_problem_scene(
                1,
                "Create Variables",
                "Create three variables: your name, age, and favorite color. Print all three.",
                "easy"
            ),
            builder.create_solution_scene(
                "Solution",
                ["name = 'Alice'", "age = 25", "color = 'blue'", "print(name, age, color)"],
                "Create three variables and print them together."
            ),
            builder.create_checkpoint_scene(
                1,
                ["Variable declaration", "Value assignment"],
                ["Can you create variables?"],
                ["Functions", "Loops"]
            )
        ]
    )

    # Lesson 2: Functions
    builder.add_video(
        video_id="02_functions",
        title="Functions",
        description="Learn about functions",
        scenes=[
            builder.create_learning_objectives_scene(
                "Lesson 2: Functions",
                ["Define functions", "Use parameters", "Return values"],
                {'duration': 12, 'difficulty': 'beginner'}
            ),
            builder.create_title_scene("Functions", "Reusable Code"),
            builder.create_command_scene(
                "Function Definition",
                "Creating Functions",
                ["def add(a, b):", "    return a + b", "", "result = add(3, 5)"]
            ),
            builder.create_problem_scene(
                2,
                "Multiply Function",
                "Write a function that multiplies two numbers and returns the result.",
                "easy"
            ),
            builder.create_solution_scene(
                "Solution",
                ["def multiply(a, b):", "    return a * b", "", "print(multiply(4, 5))  # 20"],
                "Multiply two numbers and return the product."
            ),
            builder.create_quiz_scene(
                "What does 'return' do in a function?",
                ["A: Ends the program", "B: Sends a value back", "C: Prints to console", "D: Deletes the function"],
                "B: Sends a value back",
                show_answer=True
            ),
            builder.create_checkpoint_scene(
                2,
                ["Functions", "Parameters", "Return values"],
                ["Can you write a function?"],
                ["Loops", "Conditionals"]
            )
        ]
    )

    # Lesson 3: Loops
    builder.add_video(
        video_id="03_loops",
        title="Loops",
        description="Learn about loops",
        scenes=[
            builder.create_learning_objectives_scene(
                "Lesson 3: Loops",
                ["Use for loops", "Use while loops", "Understand iteration"],
                {'duration': 15, 'difficulty': 'intermediate'}
            ),
            builder.create_title_scene("Loops", "Repetition in Code"),
            builder.create_command_scene(
                "For Loops",
                "Iterating Over Lists",
                ["for i in range(5):", "    print(i)", "→ 0 1 2 3 4"]
            ),
            builder.create_exercise_scene(
                "Loop Practice",
                [
                    "Create a list of 5 names",
                    "Use a for loop to print each name",
                    "Add 'Hello, ' before each name"
                ],
                difficulty="medium",
                estimated_time="15 minutes"
            ),
            builder.create_checkpoint_scene(
                3,
                ["Variables", "Functions", "Loops"],
                ["Understand all basics?"],
                ["Conditionals", "Data structures"]
            )
        ]
    )

    # Export
    builder.export_to_yaml('../sets/python_course_educational')

    print("\n✓ Complete educational course created!")
    print(f"  Lessons: {len(builder.videos)}")
    print("  Location: sets/python_course_educational/")
    print("\nThis course includes:")
    print("  • Learning objectives for each lesson")
    print("  • Coding problems and solutions")
    print("  • Quiz questions with answers")
    print("  • Practice exercises")
    print("  • Progress checkpoints")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Educational course examples')
    parser.add_argument(
        '--example',
        choices=['lesson', 'course'],
        default='lesson',
        help='Which example to run'
    )

    args = parser.parse_args()

    if args.example == 'lesson':
        asyncio.run(create_complete_educational_lesson())
    elif args.example == 'course':
        asyncio.run(create_educational_course_series())


if __name__ == "__main__":
    main()

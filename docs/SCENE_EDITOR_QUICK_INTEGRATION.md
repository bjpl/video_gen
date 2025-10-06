# Scene Editor - Quick Integration Guide

## 🚀 Fast Implementation Steps

### 1️⃣ Update Data Structures (Line ~1089 in create.html)

**FIND:**
```javascript
videos: [{
    title: '',
    voices: ['male'],
    duration: null
}],
```

**REPLACE WITH:**
```javascript
videos: [{
    title: '',
    voices: ['male'],
    duration: null,
    scenes: [{ type: 'title', title: '', subtitle: '' }],
    showScenes: false
}],
```

**Do this for BOTH `single.videos` and each video in `set.videos`**

---

### 2️⃣ Add JavaScript Functions (After line ~1260, after removeVoiceTrack)

**INSERT:**
```javascript
addScene(mode, videoIdx, sceneType) {
    const config = mode === 'single' ? this.single : this.set;
    if (!config.videos[videoIdx].scenes) {
        config.videos[videoIdx].scenes = [];
    }

    const sceneTemplates = {
        title: { type: 'title', title: '', subtitle: '' },
        command: { type: 'command', header: '', description: '', commands: '' },
        list: { type: 'list', header: '', description: '', items: '' },
        outro: { type: 'outro', message: '', cta: '' },
        quiz: { type: 'quiz', question: '', options: '', answer: '' },
        slide: { type: 'slide', header: '', content: '' }
    };

    config.videos[videoIdx].scenes.push(sceneTemplates[sceneType] || sceneTemplates.title);
},

removeScene(mode, videoIdx, sceneIdx) {
    const config = mode === 'single' ? this.single : this.set;
    if (config.videos[videoIdx].scenes && config.videos[videoIdx].scenes.length > 0) {
        config.videos[videoIdx].scenes.splice(sceneIdx, 1);
    }
},
```

---

### 3️⃣ Update updateVideoList Function (Line ~1228)

**FIND:**
```javascript
config.videos.push({
    title: `Video ${i + 1}`,
    voices: ['male'],
    duration: null
});
```

**REPLACE WITH:**
```javascript
config.videos.push({
    title: `Video ${i + 1}`,
    voices: ['male'],
    duration: null,
    scenes: [{ type: 'title', title: '', subtitle: '' }],
    showScenes: false
});
```

---

### 4️⃣ Insert HTML Component (After line ~392, after Duration Override)

**LOCATION:** Find "<!-- Scene Builder Integration -->" comment

**INSERT BEFORE IT:** (Copy entire content from scene_editor_component.html)

```html
<!-- Scene Editor -->
<div class="mt-4 border-t pt-4">
    <button @click="single.videos[0].showScenes = !single.videos[0].showScenes" type="button"
            class="w-full flex items-center justify-between px-4 py-3 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-lg transition-all">
        <div class="flex items-center gap-2">
            <span class="text-lg">📝</span>
            <span class="font-semibold text-gray-900">Edit Scenes</span>
            <span class="text-xs bg-purple-500 text-white px-2 py-0.5 rounded-full" x-text="(single.videos[0].scenes || []).length + ' scenes'"></span>
        </div>
        <svg class="w-5 h-5 transition-transform" :class="single.videos[0].showScenes ? 'rotate-180' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
        </svg>
    </button>

    <div x-show="single.videos[0].showScenes" x-collapse class="mt-3 space-y-3">
        <!-- Scene Type Quick-Add Buttons -->
        <div>
            <label class="block text-xs font-medium text-gray-600 mb-2">ADD SCENE TYPE</label>
            <div class="grid grid-cols-3 sm:grid-cols-6 gap-2">
                <button @click="addScene('single', 0, 'title')" type="button"
                        class="px-2 py-2 text-xs bg-white hover:bg-blue-50 border border-blue-300 rounded-lg font-medium transition-colors">
                    🎬 Title
                </button>
                <button @click="addScene('single', 0, 'command')" type="button"
                        class="px-2 py-2 text-xs bg-white hover:bg-green-50 border border-green-300 rounded-lg font-medium transition-colors">
                    💻 Code
                </button>
                <button @click="addScene('single', 0, 'list')" type="button"
                        class="px-2 py-2 text-xs bg-white hover:bg-yellow-50 border border-yellow-300 rounded-lg font-medium transition-colors">
                    📋 List
                </button>
                <button @click="addScene('single', 0, 'outro')" type="button"
                        class="px-2 py-2 text-xs bg-white hover:bg-purple-50 border border-purple-300 rounded-lg font-medium transition-colors">
                    👋 Outro
                </button>
                <button @click="addScene('single', 0, 'quiz')" type="button"
                        class="px-2 py-2 text-xs bg-white hover:bg-pink-50 border border-pink-300 rounded-lg font-medium transition-colors">
                    ❓ Quiz
                </button>
                <button @click="addScene('single', 0, 'slide')" type="button"
                        class="px-2 py-2 text-xs bg-white hover:bg-cyan-50 border border-cyan-300 rounded-lg font-medium transition-colors">
                    📊 Slide
                </button>
            </div>
        </div>

        <!-- Scene List -->
        <div class="space-y-2">
            <template x-for="(scene, sIdx) in (single.videos[0].scenes || [])" :key="sIdx">
                <div class="p-3 bg-white border-2 border-gray-200 rounded-lg hover:border-blue-300 transition-colors">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-lg cursor-move">⋮⋮</span>
                        <span class="text-xs font-semibold text-gray-500 uppercase" x-text="scene.type"></span>
                        <span class="text-xs text-gray-400">#<span x-text="sIdx + 1"></span></span>
                        <button @click="removeScene('single', 0, sIdx)" type="button"
                                class="ml-auto text-red-500 hover:text-red-700 font-bold text-lg px-2">×</button>
                    </div>

                    <!-- Dynamic Form Based on Scene Type -->
                    <div class="space-y-2">
                        <!-- Title Scene -->
                        <template x-if="scene.type === 'title'">
                            <div class="space-y-2">
                                <input x-model="scene.title" type="text" placeholder="Main Title"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                                <input x-model="scene.subtitle" type="text" placeholder="Subtitle (optional)"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                            </div>
                        </template>

                        <!-- Command/Code Scene -->
                        <template x-if="scene.type === 'command'">
                            <div class="space-y-2">
                                <input x-model="scene.header" type="text" placeholder="Section Header"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500">
                                <input x-model="scene.description" type="text" placeholder="Description"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500">
                                <textarea x-model="scene.commands" placeholder="Commands (one per line)" rows="3"
                                          class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 font-mono"></textarea>
                            </div>
                        </template>

                        <!-- List Scene -->
                        <template x-if="scene.type === 'list'">
                            <div class="space-y-2">
                                <input x-model="scene.header" type="text" placeholder="List Header"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500">
                                <input x-model="scene.description" type="text" placeholder="Description (optional)"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500">
                                <textarea x-model="scene.items" placeholder="List items (one per line)" rows="3"
                                          class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500"></textarea>
                            </div>
                        </template>

                        <!-- Outro Scene -->
                        <template x-if="scene.type === 'outro'">
                            <div class="space-y-2">
                                <input x-model="scene.message" type="text" placeholder="Closing Message"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                                <input x-model="scene.cta" type="text" placeholder="Call to Action (optional)"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                            </div>
                        </template>

                        <!-- Quiz Scene -->
                        <template x-if="scene.type === 'quiz'">
                            <div class="space-y-2">
                                <input x-model="scene.question" type="text" placeholder="Question"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-500">
                                <textarea x-model="scene.options" placeholder="Options (one per line)" rows="3"
                                          class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-500"></textarea>
                                <input x-model="scene.answer" type="text" placeholder="Correct Answer"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-pink-500">
                            </div>
                        </template>

                        <!-- Slide Scene -->
                        <template x-if="scene.type === 'slide'">
                            <div class="space-y-2">
                                <input x-model="scene.header" type="text" placeholder="Slide Header"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-cyan-500">
                                <textarea x-model="scene.content" placeholder="Slide Content" rows="3"
                                          class="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-cyan-500"></textarea>
                            </div>
                        </template>
                    </div>
                </div>
            </template>

            <!-- Empty State -->
            <div x-show="!(single.videos[0].scenes || []).length" class="text-center py-8 text-gray-400 border-2 border-dashed border-gray-200 rounded-lg">
                <div class="text-3xl mb-2">🎬</div>
                <div class="text-sm">No scenes yet. Click a button above to add your first scene.</div>
            </div>
        </div>
    </div>
</div>
```

---

### 5️⃣ Update Generate Functions (Lines ~1286 and ~1400)

**In generateSingle() - manual input section:**
```javascript
const videoData = {
    video_id: 'single_' + Date.now(),
    title: this.single.videos[0].title || this.single.title || 'Single Video',
    voices: this.single.videos[0].voices,
    duration: this.single.videos[0].duration || this.single.duration,
    scenes: this.single.videos[0].scenes || []  // ADD THIS LINE
};
```

**In generateSet() - manual input section:**
```javascript
const videosData = this.set.videos.map((video, i) => ({
    video_id: `video_${i+1}`,
    title: video.title || `Video ${i+1}`,
    voices: video.voices,
    duration: video.duration || this.set.duration,
    scenes: video.scenes || []  // ADD THIS LINE
}));
```

---

## ✅ Verification

After integration, verify:

1. **Browser Console:** No JavaScript errors
2. **Scene Editor Button:** Toggles panel correctly
3. **Add Scene:** Each button creates appropriate scene form
4. **Remove Scene:** X button removes scene from list
5. **Scene Count Badge:** Updates with scene additions/removals
6. **Empty State:** Shows when all scenes removed
7. **Data Binding:** Input fields update scene data
8. **API Payload:** Check network tab to see scenes in POST body

---

## 🔧 Troubleshooting

**Panel won't toggle:**
- Check `x-collapse` directive is working (Alpine.js loaded)
- Verify `showScenes` property initialized in video object

**Scenes not appearing:**
- Verify `scenes` array initialized in video object
- Check Alpine.js template syntax (x-for, x-if)

**Scenes not in API payload:**
- Ensure generateSingle/Set functions include `scenes` field
- Check JSON stringify in network request

**Scene type buttons don't work:**
- Verify `addScene()` function is defined
- Check scene type string matches template keys

---

## 📋 Complete File Paths

- **Main file to edit:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\create.html`
- **Reference HTML:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\scene_editor_component.html`
- **Reference JS:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\app\templates\scene_editor_functions.js`
- **Full docs:** `C:\Users\brand\Development\Project_Workspace\active-development\video_gen\docs\SCENE_EDITOR_IMPLEMENTATION.md`

---

**Ready to integrate!** 🚀
